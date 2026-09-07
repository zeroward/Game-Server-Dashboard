package portal

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"waypoint/internal/vpn"
)

// Only this module handles device private material. It is never put in a Page,
// a session, a notification, the gateway protocol, or a persistent plaintext file.
func (a *App) initDelivery() error {
	dir := a.Config.VPNDeliveryDir
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(dir, "delivery.key")
	key, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		var n int
		if e = a.Store.DB.QueryRow("SELECT count(*) FROM vpn_deliveries WHERE encrypted_key IS NOT NULL").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return errors.New("Delivery encryption key is missing; restore the separate delivery volume before starting")
		}
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return e
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, e = f.Write(key)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e != nil {
		return e
	}
	defer clear(key)
	if len(key) != 32 {
		return errors.New("Invalid delivery encryption key")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	a.deliveryCipher, e = cipher.NewGCMWithRandomNonce(block)
	return e
}
func deliveryAAD(owner, device int, pub string) []byte {
	return []byte(fmt.Sprintf("waypoint-pack-v1:%d:%d:%s", owner, device, pub))
}

// The same signed-in audience rules as catalog discovery, evaluated inside the
// transaction that creates/delivers a pack so concurrent visibility changes serialize.
func packServiceAllowed(tx *sql.Tx, u *User, id int) bool {
	var au, cat string
	var grant, catGrant int
	e := tx.QueryRow(`SELECT s.audience,coalesce(nullif(s.access_service,0),s.id),coalesce(c.audience,'member'),coalesce(c.access_service,0) FROM services s LEFT JOIN categories c ON c.id=s.category_id WHERE s.id=? AND s.published=1 AND s.archived=0`, id).Scan(&au, &grant, &cat, &catGrant)
	if e != nil {
		return false
	}
	allowed := func(aud string, sid int) bool {
		if u.Role == "admin" {
			return true
		}
		if aud == "member" || aud == "public" {
			return true
		}
		if aud != "access" {
			return false
		}
		var n int
		e := tx.QueryRow("SELECT count(*) FROM access_records WHERE user_id=? AND service_id=? AND state='active' AND (expires='' OR expires>?)", u.ID, sid, now()).Scan(&n)
		return e == nil && n > 0
	}
	return allowed(au, grant) && allowed(cat, catGrant)
}
func packOwner(tx *sql.Tx, u *User) error {
	var role string
	var generation int
	if e := tx.QueryRow("SELECT role,generation FROM users WHERE id=? AND enabled=1", u.ID).Scan(&role, &generation); e != nil || role != u.Role || generation != u.Generation {
		return errors.New("Your account changed; sign in again")
	}
	return nil
}

// Creation, optional old-device retirement, public enrollment, encrypted secret,
// and access request are one transaction. Retried submissions cannot create twins.
func (a *App) createPackDevice(u *User, name string, target int, reason string, replace, version int, confirm bool) (int, error) {
	if a.deliveryCipher == nil {
		return 0, errors.New("Automatic connection packs are not configured")
	}
	name = strings.TrimSpace(name)
	reason = strings.TrimSpace(reason)
	if name == "" || len(name) > 80 || len(reason) < 3 || len(reason) > 2000 {
		return 0, errors.New("Enter a device name and a short explanation of what you want to use")
	}
	if replace != 0 && !confirm {
		return 0, errors.New("Confirm replacing this device; its old connection will be retired")
	}
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return 0, errors.New("Could not prepare this device")
	}
	key := private.Bytes()
	defer clear(key)
	pub := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
	var id int
	e = a.Store.Write(func(tx *sql.Tx) error {
		if e := packOwner(tx, u); e != nil {
			return e
		}
		var sid int
		var label, service string
		if e := tx.QueryRow("SELECT t.service_id,t.label,s.name FROM vpn_targets t JOIN services s ON s.id=t.service_id WHERE t.id=? AND t.enabled=1", target).Scan(&sid, &label, &service); e != nil || !packServiceAllowed(tx, u, sid) {
			return errors.New("That service is unavailable for a connection request")
		}
		if replace != 0 {
			var owner, oldVersion int
			var state string
			if e := tx.QueryRow("SELECT user_id,version,state FROM vpn_devices WHERE id=?", replace).Scan(&owner, &oldVersion, &state); e != nil || owner != u.ID || oldVersion != version || state == "revoked" {
				return errors.New("This device changed or is unavailable; reload before replacing it")
			}
			if _, e := tx.Exec("INSERT INTO vpn_history(grant_id,actor_id,state,cidr,protocol,ports,expires,created) SELECT id,?,'Revoked',cidr,protocol,ports,expires,? FROM vpn_grants WHERE device_id=? AND state IN ('Pending','Approved')", u.ID, now(), replace); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE vpn_grants SET state='Revoked',explanation='Connection pack replaced; new approval required.',version=version+1 WHERE device_id=? AND state IN ('Pending','Approved')", replace); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE vpn_devices SET state='revoked',version=version+1 WHERE id=?", replace); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE vpn_deliveries SET encrypted_key=NULL WHERE device_id=?", replace); e != nil {
				return e
			}
			if e := audit(tx, u.ID, "vpn.pack.replace", idTarget("device", replace)); e != nil {
				return e
			}
		}
		var duplicate int
		if e := tx.QueryRow("SELECT count(*) FROM vpn_devices WHERE user_id=? AND name=? COLLATE NOCASE AND state!='revoked'", u.ID, name).Scan(&duplicate); e != nil {
			return e
		}
		if duplicate != 0 {
			return errors.New("A device already uses that name. Open it below or choose a different name.")
		}
		var e error
		id, e = enrollDevice(tx, u, name, pub)
		if e != nil {
			return e
		}
		encrypted := a.deliveryCipher.Seal(nil, nil, key, deliveryAAD(u.ID, id, pub))
		if _, e = tx.Exec("INSERT INTO vpn_deliveries(device_id,encrypted_key,expires,created) VALUES(?,?,?,?)", id, encrypted, stamp(time.Now().Add(30*24*time.Hour)), now()); e != nil {
			return e
		}
		res, e := tx.Exec("INSERT INTO vpn_grants(device_id,target_id,reason,target_label,service_name,created) VALUES(?,?,?,?,?,?)", id, target, reason, label, service, now())
		if e != nil {
			return e
		}
		gid, _ := res.LastInsertId()
		if e = vpnHistory(tx, u.ID, int(gid)); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO notifications(user_id,device_id,text,created) SELECT id,?,'A device connection request needs review.',? FROM users WHERE role='admin' AND enabled=1", id, now()); e != nil {
			return e
		}
		return audit(tx, u.ID, "vpn.pack.prepare", idTarget("device", id))
	})
	return id, e
}

// Build and consume under the same transaction as owner, expiry, publication and
// applied-policy checks. Exactly one request gets bytes; build failures roll back.
func (a *App) consumePack(u *User, id int) ([]byte, error) {
	if a.deliveryCipher == nil {
		return nil, errors.New("Connection packs are unavailable")
	}
	var pack []byte
	e := a.Store.Write(func(tx *sql.Tx) error {
		if e := packOwner(tx, u); e != nil {
			return e
		}
		var pub, address, expiry, state string
		var encrypted []byte
		e := tx.QueryRow("SELECT d.public_key,d.address,p.expires,d.state,p.encrypted_key FROM vpn_devices d JOIN vpn_deliveries p ON p.device_id=d.id WHERE d.id=? AND d.user_id=? AND p.consumed IS NULL", id, u.ID).Scan(&pub, &address, &expiry, &state, &encrypted)
		if e != nil || encrypted == nil || state != "approved" || expiry <= now() {
			return errors.New("This pack is unavailable, expired, or already downloaded. Open My Devices for next steps.")
		}
		snapshot, e := vpnSnapshot(tx)
		if e != nil {
			return errors.New("Gateway policy unavailable")
		}
		var revision, serverKey, seen string
		if e = tx.QueryRow("SELECT revision,public_key,seen FROM vpn_status WHERE id=1").Scan(&revision, &serverKey, &seen); e != nil {
			return e
		}
		checked, e := time.Parse(time.RFC3339, seen)
		if e != nil || time.Since(checked) < 0 || time.Since(checked) > 20*time.Second || revision != snapshot.Revision || !vpn.Key(serverKey) {
			return errors.New("Your connection is awaiting gateway confirmation. Refresh My Devices in a moment.")
		}
		var peer vpn.Peer
		for _, candidate := range snapshot.Peers {
			if candidate.ID == id {
				peer = candidate
			}
		}
		var permitted []vpn.Rule
		for _, rule := range peer.Rules {
			var sid int
			if tx.QueryRow("SELECT t.service_id FROM vpn_grants g JOIN vpn_targets t ON t.id=g.target_id WHERE g.id=?", rule.ID).Scan(&sid) == nil && packServiceAllowed(tx, u, sid) {
				permitted = append(permitted, rule)
			}
		}
		peer.Rules = permitted
		if len(peer.Rules) == 0 {
			return errors.New("There are no current approved connections for this device")
		}
		private, e := a.deliveryCipher.Open(nil, nil, encrypted, deliveryAAD(u.ID, id, pub))
		if e != nil {
			return errors.New("This pack could not be opened; ask the administrator to check delivery storage")
		}
		defer clear(private)
		parsed, e := ecdh.X25519().NewPrivateKey(private)
		if e != nil || base64.StdEncoding.EncodeToString(parsed.PublicKey().Bytes()) != pub {
			return errors.New("Device key verification failed")
		}
		pack, e = connectionPack(id, private, address, serverKey, a.Config.VPNEndpoint, vpn.Routes(peer))
		if e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE vpn_deliveries SET encrypted_key=NULL,consumed=? WHERE device_id=?", now(), id); e != nil {
			return e
		}
		return audit(tx, u.ID, "vpn.pack.download", idTarget("device", id))
	})
	if e != nil {
		clear(pack)
		return nil, e
	}
	return pack, nil
}
func connectionPack(id int, private []byte, address, serverKey, endpoint, routes string) ([]byte, error) {
	if !vpn.Endpoint(endpoint) || !vpn.Key(serverKey) || routes == "" {
		return nil, errors.New("Connection settings are incomplete")
	}
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", base64.StdEncoding.EncodeToString(private), address, serverKey, endpoint, routes)
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, file := range [][2]string{{fmt.Sprintf("wp%d.conf", id), conf}, {"READ-ME.txt", `Your Waypoint connection

1. Install the official WireGuard app: https://www.wireguard.com/install/
2. Extract this ZIP (Windows: right-click > Extract All; macOS: double-click;
   iPhone/iPad: tap the ZIP in Files; Android: extract using your Files app).
3. Open WireGuard. Choose Add tunnel / Import from file, then select wp` + fmt.Sprint(id) + `.conf.
4. Turn on that tunnel. Return to Waypoint and open your approved service.

You do not need to open or edit the configuration, or copy any keys.
Use this pack on ONE device. Add another device in Waypoint for another computer
or phone. This file contains your private connection key: do not share it or
paste it into a ticket. After importing, remove the ZIP and extracted files
from Downloads, shared folders, and cloud-synced storage.

Waypoint offers this pack once. If you lose it or need an updated pack, choose
Replace connection pack in My Devices. Replacement retires the old connection
and needs administrator approval again. Additional destinations may require an
updated pack. Expiring the download does not disable a VPN peer; your approved
network permissions have their own expiry, enforced at the gateway.

Only approved destinations work. This is not general access to your friend's
network or a replacement for the service's account. DNS settings stay unchanged.
For help, open the relevant service in Waypoint and choose Get Help. Never attach
or paste this configuration into the discussion.
`}} {
		h := &zip.FileHeader{Name: file[0], Method: zip.Store}
		h.SetMode(0600)
		w, e := z.CreateHeader(h)
		if e != nil {
			return nil, e
		}
		if _, e = w.Write([]byte(file[1])); e != nil {
			return nil, e
		}
	}
	if e := z.Close(); e != nil {
		return nil, e
	}
	return buf.Bytes(), nil
}
func (a *App) downloadPack(w http.ResponseWriter, r *http.Request) {
	if !a.Config.VPNEnabled {
		a.fail(w, r, 404, "Connection packs are unavailable.")
		return
	}
	u := a.member(w, r)
	if u == nil {
		return
	}
	if a.Store.Limited(fmt.Sprintf("pack:%d", u.ID), 10, 15*time.Minute) {
		a.fail(w, r, 429, "Too many download attempts. Try again later.")
		return
	}
	pack, e := a.consumePack(u, number(r.PathValue("id")))
	if e != nil {
		a.fail(w, r, 409, e.Error())
		return
	}
	defer clear(pack)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=waypoint-device-%d.zip", number(r.PathValue("id"))))
	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Length", fmt.Sprint(len(pack)))
	w.Write(pack)
}

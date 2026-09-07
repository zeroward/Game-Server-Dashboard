package portal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"waypoint/internal/vpn"
)

type Device struct {
	PackPending                                        bool
	PackMode, PackReady, PackGone, PackDownloaded      bool
	PackExpires                                        string
	ID, UserID, Version                                int
	Name, Username, PublicKey, Address, State, Created string
	Grants                                             []NetworkGrant
	Routes                                             string
}
type NetworkTarget struct {
	ID, ServiceID, Version                    int
	Label, ServiceName, CIDR, Protocol, Ports string
	Enabled                                   bool
}
type NetworkGrant struct {
	ID, DeviceID, TargetID, Version, TargetVersion                                          int
	Label, ServiceName, State, Reason, Explanation, CIDR, Protocol, Ports, Expires, Created string
}
type VPNPage struct {
	PacksEnabled                                 bool
	History                                      [][]string
	Devices                                      []Device
	Targets                                      []NetworkTarget
	Revision, Applied, Seen, PublicKey, Endpoint string
	Connected, Current                           bool
}

func (s *Store) VPNTargets() ([]NetworkTarget, error) {
	rows, e := s.DB.Query("SELECT t.id,t.service_id,t.version,t.label,s.name,t.cidr,t.protocol,t.ports,t.enabled FROM vpn_targets t JOIN services s ON s.id=t.service_id ORDER BY t.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []NetworkTarget
	for rows.Next() {
		var t NetworkTarget
		if e = rows.Scan(&t.ID, &t.ServiceID, &t.Version, &t.Label, &t.ServiceName, &t.CIDR, &t.Protocol, &t.Ports, &t.Enabled); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) VPNDevices(u *User) ([]Device, error) {
	q := "SELECT d.id,d.user_id,d.version,d.name,u.username,d.public_key,d.address,d.state,d.created FROM vpn_devices d JOIN users u ON u.id=d.user_id"
	var args []any
	if u.Role != "admin" {
		q += " WHERE d.user_id=?"
		args = append(args, u.ID)
	}
	q += " ORDER BY d.id DESC"
	rows, e := s.DB.Query(q, args...)
	if e != nil {
		return nil, e
	}
	var out []Device
	for rows.Next() {
		var d Device
		if e = rows.Scan(&d.ID, &d.UserID, &d.Version, &d.Name, &d.Username, &d.PublicKey, &d.Address, &d.State, &d.Created); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, d)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range out {
		rows, e = s.DB.Query("SELECT g.id,g.device_id,g.target_id,g.version,g.target_label,g.service_name,g.state,g.reason,g.explanation,g.cidr,g.protocol,g.ports,g.expires,g.created FROM vpn_grants g JOIN vpn_targets t ON t.id=g.target_id JOIN services s ON s.id=t.service_id WHERE g.device_id=? ORDER BY g.id DESC", out[i].ID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var g NetworkGrant
			if e = rows.Scan(&g.ID, &g.DeviceID, &g.TargetID, &g.Version, &g.Label, &g.ServiceName, &g.State, &g.Reason, &g.Explanation, &g.CIDR, &g.Protocol, &g.Ports, &g.Expires, &g.Created); e != nil {
				rows.Close()
				return nil, e
			}
			if g.State == "Approved" && g.Expires <= now() {
				g.State = "Expired"
			}
			// Submitted requests remain historical, but unapproved/removed routes are never disclosed.
			out[i].Grants = append(out[i].Grants, g)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	// Filter only after closing rows: this store deliberately uses one connection.
	if u.Role != "admin" {
		targets, _ := s.VPNTargets()
		for i := range out {
			for j := range out[i].Grants {
				g := &out[i].Grants[j]
				var target *NetworkTarget
				for _, t := range targets {
					if t.ID == g.TargetID {
						v := t
						target = &v
					}
				}
				var svc *Service
				if target != nil {
					svc = s.service(target.ServiceID)
				}
				if g.State != "Approved" || out[i].State != "approved" || target == nil || !target.Enabled || svc == nil || !s.discover(u, svc) {
					g.CIDR = ""
					g.Ports = ""
					g.Protocol = ""
				}
			}
		}
	}
	return out, nil
}

func (s *Store) VPNSnapshot() (vpn.Snapshot, error) { return vpnSnapshot(s.DB) }
func vpnSnapshot(q interface {
	Query(string, ...any) (*sql.Rows, error)
}) (vpn.Snapshot, error) {
	rows, e := q.Query(`SELECT d.id,d.public_key,d.address,g.id,g.cidr,g.protocol,g.ports,g.expires FROM vpn_devices d JOIN users u ON u.id=d.user_id JOIN vpn_grants g ON g.device_id=d.id JOIN vpn_targets t ON t.id=g.target_id JOIN services s ON s.id=t.service_id WHERE u.enabled=1 AND d.state='approved' AND g.state='Approved' AND g.expires>? AND t.enabled=1 AND s.published=1 AND s.archived=0 ORDER BY d.id,g.id`, now())
	if e != nil {
		return vpn.Snapshot{}, e
	}
	defer rows.Close()
	out := vpn.Snapshot{}
	for rows.Next() {
		var p vpn.Peer
		var r vpn.Rule
		if e = rows.Scan(&p.ID, &p.PublicKey, &p.Address, &r.ID, &r.CIDR, &r.Protocol, &r.Ports, &r.Expires); e != nil {
			return out, e
		}
		if len(out.Peers) == 0 || out.Peers[len(out.Peers)-1].ID != p.ID {
			out.Peers = append(out.Peers, p)
		}
		i := len(out.Peers) - 1
		out.Peers[i].Rules = append(out.Peers[i].Rules, r)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	out.Revision = out.Hash()
	return out, out.Validate()
}
func expireVPN(tx *sql.Tx) error {
	cutoff := now()
	if _, e := tx.Exec("UPDATE vpn_deliveries SET encrypted_key=NULL WHERE encrypted_key IS NOT NULL AND (expires<=? OR device_id IN (SELECT d.id FROM vpn_devices d JOIN users u ON u.id=d.user_id WHERE d.state='revoked' OR u.enabled=0))", cutoff); e != nil {
		return e
	}
	for _, query := range []string{
		"INSERT INTO vpn_history(grant_id,actor_id,state,cidr,protocol,ports,expires,created) SELECT id,NULL,'Expired',cidr,protocol,ports,expires,? FROM vpn_grants WHERE state='Approved' AND expires<=?",
		"INSERT INTO notifications(user_id,device_id,text,created) SELECT d.user_id,d.id,'Your device network permission has expired. Review My Devices.',? FROM vpn_grants g JOIN vpn_devices d ON d.id=g.device_id WHERE g.state='Approved' AND g.expires<=?",
		"INSERT INTO audit(actor_id,action,target,created) SELECT NULL,'vpn.network.expired','network-request:'||id,? FROM vpn_grants WHERE state='Approved' AND expires<=?",
	} {
		if _, e := tx.Exec(query, cutoff, cutoff); e != nil {
			return e
		}
	}
	_, e := tx.Exec("UPDATE vpn_grants SET state='Expired',version=version+1 WHERE state='Approved' AND expires<=?", cutoff)
	return e
}
func vpnHistory(tx *sql.Tx, actor, id int) error {
	_, e := tx.Exec("INSERT INTO vpn_history(grant_id,actor_id,state,cidr,protocol,ports,expires,created) SELECT id,?,state,cidr,protocol,ports,expires,? FROM vpn_grants WHERE id=?", actor, now(), id)
	return e
}
func vpnNotify(tx *sql.Tx, user, device int, text string) error {
	_, e := tx.Exec("INSERT INTO notifications(user_id,device_id,text,created) VALUES(?,?,?,?)", user, device, text, now())
	return e
}
func (s *Store) EnrollDevice(u *User, name, key string) error {
	name = strings.TrimSpace(name)
	key = strings.TrimSpace(key)
	if name == "" || len(name) > 80 || !vpn.Key(key) {
		return errors.New("Enter a device name (up to 80 characters) and a valid WireGuard public key. Never submit its private key.")
	}
	return s.Write(func(tx *sql.Tx) error { _, e := enrollDevice(tx, u, name, key); return e })
}
func enrollDevice(tx *sql.Tx, u *User, name, key string) (int, error) {
	var enabled bool
	if e := tx.QueryRow("SELECT enabled FROM users WHERE id=?", u.ID).Scan(&enabled); e != nil || !enabled {
		return 0, errors.New("Member unavailable")
	}
	var n int
	if e := tx.QueryRow("SELECT count(*) FROM vpn_devices WHERE user_id=? AND state!='revoked'", u.ID).Scan(&n); e != nil {
		return 0, e
	}
	if n >= 10 {
		return 0, errors.New("At most 10 current devices per member")
	}
	rows, e := tx.Query("SELECT address FROM vpn_devices")
	if e != nil {
		return 0, e
	}
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if e = rows.Scan(&ip); e != nil {
			rows.Close()
			return 0, e
		}
		used[ip] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	address := ""
	for i := 2; i < 255; i++ {
		v := fmt.Sprintf("10.77.0.%d/32", i)
		if !used[v] {
			address = v
			break
		}
	}
	if address == "" {
		return 0, errors.New("Device address pool exhausted; ask the administrator")
	}
	res, e := tx.Exec("INSERT INTO vpn_devices(user_id,name,public_key,address,created) VALUES(?,?,?,?,?)", u.ID, name, key, address, now())
	if e != nil {
		return 0, errors.New("This public key is already enrolled or the device could not be saved")
	}
	id, _ := res.LastInsertId()
	return int(id), audit(tx, u.ID, "vpn.device.enroll", idTarget("device", int(id)))
}

func (s *Store) RequestNetwork(u *User, device, target int, reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 || len(reason) > 2000 {
		return errors.New("Explain the intended use in 3–2000 characters; omit secrets")
	}
	var selected *NetworkTarget
	targets, e := s.VPNTargets()
	if e != nil {
		return e
	}
	for _, t := range targets {
		if t.ID == target {
			v := t
			selected = &v
		}
	}
	if selected == nil || !selected.Enabled {
		return errors.New("Network offering unavailable")
	}
	svc := s.service(selected.ServiceID)
	if svc == nil || !s.discover(u, svc) {
		return errors.New("Network offering unavailable")
	}
	return s.Write(func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRow("SELECT count(*) FROM vpn_devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND d.user_id=? AND d.state!='revoked' AND u.enabled=1", device, u.ID).Scan(&n); e != nil || n != 1 {
			return errors.New("Device unavailable")
		}
		// Historical approved grants whose time has elapsed no longer block a new request.
		if e = expireVPN(tx); e != nil {
			return e
		}
		res, e := tx.Exec("INSERT INTO vpn_grants(device_id,target_id,reason,target_label,service_name,created) VALUES(?,?,?,?,?,?)", device, target, reason, selected.Label, svc.Name, now())
		if e != nil {
			return errors.New("There is already a pending or approved request for this device and destination")
		}
		id, _ := res.LastInsertId()
		if _, e = tx.Exec("INSERT INTO notifications(user_id,device_id,text,created) SELECT id,?,'A device network request needs review.',? FROM users WHERE role='admin' AND enabled=1", device, now()); e != nil {
			return e
		}
		if e = vpnHistory(tx, u.ID, int(id)); e != nil {
			return e
		}
		return audit(tx, u.ID, "vpn.network.request", idTarget("network-request", int(id)))
	})
}
func (s *Store) DecideNetwork(u *User, id, version, targetVersion int, state, expiry, explanation string, confirmed bool) error {
	if u.Role != "admin" {
		return errors.New("Administrator required")
	}
	if state != "Approved" && state != "Denied" && state != "Revoked" {
		return errors.New("Invalid decision")
	}
	explanation = strings.TrimSpace(explanation)
	if len(explanation) < 3 || len(explanation) > 2000 {
		return errors.New("Provide a non-secret explanation (3–2000 characters)")
	}
	if state == "Approved" {
		t, e := time.Parse("2006-01-02", expiry)
		if e != nil || !t.After(time.Now()) || t.After(time.Now().Add(365*24*time.Hour)) || !confirmed {
			return errors.New("Confirm device and route approval and choose an expiry within one year (00:00 UTC)")
		}
		expiry = stamp(t)
	}
	return s.Write(func(tx *sql.Tx) error {
		var d, uid, tv int
		var old, ds, cidr, proto, ports string
		var enabled, published, archived, targetEnabled bool
		e := tx.QueryRow(`SELECT g.state,d.id,d.user_id,d.state,u.enabled,s.published,s.archived,t.enabled,t.cidr,t.protocol,t.ports,t.version FROM vpn_grants g JOIN vpn_devices d ON d.id=g.device_id JOIN users u ON u.id=d.user_id JOIN vpn_targets t ON t.id=g.target_id JOIN services s ON s.id=t.service_id WHERE g.id=? AND g.version=?`, id, version).Scan(&old, &d, &uid, &ds, &enabled, &published, &archived, &targetEnabled, &cidr, &proto, &ports, &tv)
		if e != nil {
			return errors.New("Request changed; reload before deciding")
		}
		if !(old == "Pending" && (state == "Approved" || state == "Denied") || old == "Approved" && state == "Revoked") {
			return errors.New("Illegal network request transition")
		}
		if state == "Approved" {
			var active int
			if e := tx.QueryRow("SELECT count(*) FROM vpn_grants WHERE state='Approved' AND expires>?", now()).Scan(&active); e != nil {
				return e
			}
			if active >= 1024 {
				return errors.New("Gateway policy limit reached (1024 active grants)")
			}
			if tv != targetVersion {
				return errors.New("Destination changed since review; reload before approving")
			}
			if !enabled || !published || archived || !targetEnabled || ds == "revoked" {
				return errors.New("Member, device or destination unavailable")
			}
			if e = vpn.Destination(cidr, proto, ports); e != nil {
				return e
			}
			if _, e = tx.Exec("UPDATE vpn_devices SET state='approved',version=version+1 WHERE id=?", d); e != nil {
				return e
			}
		}
		if state != "Approved" {
			if e = vpnHistory(tx, u.ID, id); e != nil {
				return e
			}
			cidr = ""
			proto = ""
			ports = ""
			expiry = ""
		}
		if _, e = tx.Exec("UPDATE vpn_grants SET state=?,cidr=?,protocol=?,ports=?,expires=?,explanation=?,version=version+1 WHERE id=? AND version=?", state, cidr, proto, ports, expiry, explanation, id, version); e != nil {
			return e
		}
		if e = vpnHistory(tx, u.ID, id); e != nil {
			return e
		}
		if e = vpnNotify(tx, uid, d, "Your device network request was updated. Open My Devices for details."); e != nil {
			return e
		}
		return audit(tx, u.ID, "vpn.network."+strings.ToLower(state), idTarget("network-request", id))
	})
}
func (s *Store) RevokeDevice(u *User, id, version int) error {
	return s.Write(func(tx *sql.Tx) error {
		var uid int
		var state string
		if e := tx.QueryRow("SELECT user_id,state FROM vpn_devices WHERE id=? AND version=?", id, version).Scan(&uid, &state); e != nil || state == "revoked" || (u.Role != "admin" && uid != u.ID) {
			return errors.New("Device unavailable or changed; reload")
		}
		if _, e := tx.Exec("UPDATE vpn_devices SET state='revoked',version=version+1 WHERE id=?", id); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO vpn_history(grant_id,actor_id,state,cidr,protocol,ports,expires,created) SELECT id,?,'Revoked',cidr,protocol,ports,expires,? FROM vpn_grants WHERE device_id=? AND state IN ('Pending','Approved')", u.ID, now(), id); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE vpn_grants SET state='Revoked',explanation='Device revoked.',version=version+1 WHERE device_id=? AND state IN ('Pending','Approved')", id); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE vpn_deliveries SET encrypted_key=NULL WHERE device_id=?", id); e != nil {
			return e
		}
		if e := vpnNotify(tx, uid, id, "Device revocation requested. My Devices shows gateway confirmation."); e != nil {
			return e
		}
		return audit(tx, u.ID, "vpn.device.revoke", idTarget("device", id))
	})
}
func (s *Store) SaveNetworkTarget(u *User, t NetworkTarget) error {
	if u.Role != "admin" {
		return errors.New("Administrator required")
	}
	if len(strings.TrimSpace(t.Label)) < 1 || len(t.Label) > 100 {
		return errors.New("Provide a short destination label")
	}
	if e := vpn.Destination(t.CIDR, t.Protocol, t.Ports); e != nil {
		return e
	}
	return s.Write(func(tx *sql.Tx) error {
		var exists int
		if e := tx.QueryRow("SELECT count(*) FROM services WHERE id=? AND archived=0", t.ServiceID).Scan(&exists); e != nil || exists != 1 {
			return errors.New("Choose an existing service")
		}
		if t.ID == 0 {
			res, e := tx.Exec("INSERT INTO vpn_targets(service_id,label,cidr,protocol,ports,enabled) VALUES(?,?,?,?,?,?)", t.ServiceID, t.Label, t.CIDR, t.Protocol, t.Ports, t.Enabled)
			if e != nil {
				return e
			}
			id, _ := res.LastInsertId()
			t.ID = int(id)
		} else {
			res, e := tx.Exec("UPDATE vpn_targets SET label=?,cidr=?,protocol=?,ports=?,enabled=?,version=version+1 WHERE id=? AND service_id=? AND version=?", t.Label, t.CIDR, t.Protocol, t.Ports, t.Enabled, t.ID, t.ServiceID, t.Version)
			if e != nil {
				return e
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return errors.New("Destination changed; reload. Its associated service cannot be changed.")
			}
		}
		return audit(tx, u.ID, "vpn.target.save", idTarget("network-target", t.ID))
	})
}
func (a *App) devices(w http.ResponseWriter, r *http.Request) {
	if !a.Config.VPNEnabled {
		a.fail(w, r, 404, "Device enrollment is not enabled.")
		return
	}
	admin := strings.HasPrefix(r.URL.Path, "/admin/")
	u := a.member(w, r)
	if u == nil {
		return
	}
	if admin && u.Role != "admin" {
		a.fail(w, r, 403, "Administrator required.")
		return
	}
	if r.Method == "POST" {
		if e := r.ParseForm(); e != nil {
			a.fail(w, r, 400, "Invalid form.")
			return
		}
		if a.Store.Limited(fmt.Sprintf("vpn:%d", u.ID), 40, 15*time.Minute) {
			a.fail(w, r, 429, "Too many device changes; try again later.")
			return
		}
		var e error
		switch r.FormValue("action") {
		case "automatic", "replacepack":
			id, err := a.createPackDevice(u, r.FormValue("name"), number(r.FormValue("target")), r.FormValue("reason"), number(r.FormValue("replace")), number(r.FormValue("version")), r.FormValue("confirm") == "yes")
			if err != nil {
				e = err
			} else {
				http.Redirect(w, r, fmt.Sprintf("/my-devices#device-%d", id), 303)
				return
			}
		case "enroll":
			e = a.Store.EnrollDevice(u, r.FormValue("name"), r.FormValue("public_key"))
		case "request":
			e = a.Store.RequestNetwork(u, number(r.FormValue("device")), number(r.FormValue("target")), r.FormValue("reason"))
		case "revoke":
			if r.FormValue("confirm") != "yes" {
				e = errors.New("Confirm device revocation")
			} else {
				e = a.Store.RevokeDevice(u, number(r.FormValue("device")), number(r.FormValue("version")))
			}
		case "decide":
			e = a.Store.DecideNetwork(u, number(r.FormValue("grant")), number(r.FormValue("version")), number(r.FormValue("target_version")), r.FormValue("state"), r.FormValue("expires"), r.FormValue("explanation"), r.FormValue("confirm") == "yes")
		case "target":
			if number(r.FormValue("id")) != 0 && r.FormValue("confirm") != "yes" {
				a.fail(w, r, 400, "Confirm this destination change.")
				return
			}
			e = a.Store.SaveNetworkTarget(u, NetworkTarget{ID: number(r.FormValue("id")), ServiceID: number(r.FormValue("service")), Version: number(r.FormValue("version")), Label: r.FormValue("label"), CIDR: r.FormValue("cidr"), Protocol: r.FormValue("protocol"), Ports: r.FormValue("ports"), Enabled: r.FormValue("enabled") == "yes"})
		default:
			e = errors.New("Unknown device action")
		}
		if e != nil {
			a.fail(w, r, 400, e.Error())
			return
		}
		http.Redirect(w, r, r.URL.Path, 303)
		return
	}
	p := a.page(r, "My Devices", "devices")
	p.VPN = &VPNPage{Endpoint: a.Config.VPNEndpoint, PacksEnabled: a.deliveryCipher != nil}
	if admin {
		p.Title = "Network access administration"
		p.AdminTab = "vpn"
		p.Services = a.Store.AllServices()
		p.VPN.History = a.queryRows("SELECT h.grant_id,coalesce(u.username,'system'),h.state,h.cidr,h.protocol,h.ports,h.expires,h.created FROM vpn_history h LEFT JOIN users u ON u.id=h.actor_id ORDER BY h.id DESC LIMIT 100")
	}
	viewer := *u
	if !admin {
		viewer.Role = "member"
	}
	devices, e := a.Store.VPNDevices(&viewer)
	if e != nil {
		a.fail(w, r, 500, "Device information unavailable.")
		return
	}
	p.VPN.Devices = devices
	targets, e := a.Store.VPNTargets()
	if e != nil {
		a.fail(w, r, 500, "Destinations unavailable.")
		return
	}
	for _, t := range targets {
		svc := a.Store.service(t.ServiceID)
		if admin {
			p.VPN.Targets = append(p.VPN.Targets, t)
		} else if t.Enabled && svc != nil && a.Store.discover(u, svc) {
			t.CIDR = ""
			t.Protocol = ""
			t.Ports = ""
			p.VPN.Targets = append(p.VPN.Targets, t)
		}
	}
	snap, e := a.Store.VPNSnapshot()
	if e != nil {
		a.fail(w, r, 500, "Network policy unavailable.")
		return
	}
	p.VPN.Revision = snap.Revision
	a.Store.DB.QueryRow("SELECT revision,public_key,seen FROM vpn_status WHERE id=1").Scan(&p.VPN.Applied, &p.VPN.PublicKey, &p.VPN.Seen)
	seen, _ := time.Parse(time.RFC3339, p.VPN.Seen)
	p.VPN.Connected = time.Since(seen) >= 0 && time.Since(seen) < 20*time.Second
	p.VPN.Current = p.VPN.Applied == snap.Revision
	for i := range p.VPN.Devices {
		d := &p.VPN.Devices[i]
		peer := vpn.Peer{}
		for j := range d.Grants {
			g := &d.Grants[j]
			if g.State == "Pending" {
				d.PackPending = true
			}
			for _, t := range targets {
				if g.TargetID == t.ID {
					g.TargetVersion = t.Version
					if admin && g.State == "Pending" {
						g.CIDR = t.CIDR
						g.Protocol = t.Protocol
						g.Ports = t.Ports
					}
				}
			}
			if g.State == "Approved" && g.CIDR != "" && d.State == "approved" {
				peer.Rules = append(peer.Rules, vpn.Rule{CIDR: g.CIDR})
			}
		}
		d.Routes = vpn.Routes(peer)
		var consumed sql.NullString
		var hasCipher bool
		if e := a.Store.DB.QueryRow("SELECT expires,consumed,encrypted_key IS NOT NULL FROM vpn_deliveries WHERE device_id=?", d.ID).Scan(&d.PackExpires, &consumed, &hasCipher); e == nil {
			d.PackMode = true
			d.PackDownloaded = consumed.Valid
			d.PackGone = consumed.Valid || !hasCipher || d.PackExpires <= now()
			d.PackReady = !admin && !d.PackGone && d.Routes != "" && p.VPN.Connected && p.VPN.Current && a.deliveryCipher != nil
		}
	}
	a.render(w, r, p)
}

// StartVPNControl exposes only a Unix socket, authenticated by a volume-scoped bearer secret.
// The gateway mounts this directory read-only; it never mounts the portal database.
func (a *App) StartVPNControl(ctx context.Context) error {
	if !a.Config.VPNEnabled {
		return nil
	}
	dir := a.Config.VPNControlDir
	if dir == "" || !vpn.Endpoint(a.Config.VPNEndpoint) {
		return errors.New("VPN requires VPN_CONTROL_DIR and a host:port VPN_ENDPOINT")
	}
	if e := os.MkdirAll(dir, 0770); e != nil {
		return e
	}
	if e := os.Chmod(dir, 0770); e != nil {
		return e
	}
	tokenPath := filepath.Join(dir, "token")
	token, e := os.ReadFile(tokenPath)
	if os.IsNotExist(e) {
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		token = []byte(hex.EncodeToString(b))
		e = os.WriteFile(tokenPath, token, 0640)
	}
	if e != nil {
		return e
	}
	if len(token) != 64 {
		return errors.New("Invalid VPN control token")
	}
	socket := filepath.Join(dir, "control.sock")
	if info, e := os.Lstat(socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("VPN socket path is not a socket")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	}
	ln, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	if e = os.Chmod(socket, 0660); e != nil {
		ln.Close()
		return e
	}
	server := &http.Server{Handler: a.VPNControlHandler(string(token)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); server.Close() }()
	go server.Serve(ln)
	return nil
}
func (a *App) VPNControlHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if !a.Config.VPNEnabled || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/v1/policy" {
			s, e := a.Store.VPNSnapshot()
			if e != nil {
				http.Error(w, "Policy unavailable", 503)
				return
			}
			json.NewEncoder(w).Encode(s)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/v1/applied" {
			var ack vpn.Ack
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if dec.Decode(&ack) != nil || !vpn.Key(ack.PublicKey) {
				http.Error(w, "Invalid acknowledgment", 400)
				return
			}
			s, e := a.Store.VPNSnapshot()
			if e != nil || s.Revision != ack.Revision {
				http.Error(w, "Policy changed", 409)
				return
			}
			e = a.Store.Write(func(tx *sql.Tx) error {
				var old string
				if e := tx.QueryRow("SELECT revision FROM vpn_status WHERE id=1").Scan(&old); e != nil {
					return e
				}
				if old != ack.Revision {
					if _, e := tx.Exec("INSERT INTO notifications(user_id,device_id,text,created) SELECT d.user_id,d.id,'The gateway confirmed the current network policy. Review My Devices.',? FROM vpn_devices d JOIN users u ON u.id=d.user_id WHERE u.enabled=1 AND EXISTS(SELECT 1 FROM vpn_grants g WHERE g.device_id=d.id)", now()); e != nil {
						return e
					}
					if e := audit(tx, 0, "vpn.gateway.applied", "network-policy:"+ack.Revision); e != nil {
						return e
					}
				}
				_, e := tx.Exec("UPDATE vpn_status SET revision=?,public_key=?,seen=? WHERE id=1", ack.Revision, ack.PublicKey, now())
				return e
			})
			if e != nil {
				http.Error(w, "Unavailable", 503)
				return
			}
			w.WriteHeader(204)
			return
		}
		http.NotFound(w, r)
	})
}

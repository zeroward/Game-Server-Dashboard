package portal

import (
	"archive/zip"
	"bytes"
	"crypto/ecdh"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"waypoint/web"
)

func packFixture(t *testing.T) (*App, *User, *User, *User, int) {
	t.Helper()
	a, admin, alice, bob, target := vpnFixture(t)
	a.Config.VPNDeliveryDir = t.TempDir()
	if e := a.initDelivery(); e != nil {
		t.Fatal(e)
	}
	id, e := a.createPackDevice(alice, "Simple laptop", target.ID, "Use the workspace", 0, 0, false)
	if e != nil {
		t.Fatal(e)
	}
	return a, admin, alice, bob, id
}
func approvePack(t *testing.T, a *App, admin *User, id int) {
	t.Helper()
	var gid, version, targetVersion int
	if e := a.Store.DB.QueryRow("SELECT g.id,g.version,t.version FROM vpn_grants g JOIN vpn_targets t ON t.id=g.target_id WHERE g.device_id=? AND g.state='Pending'", id).Scan(&gid, &version, &targetVersion); e != nil {
		t.Fatal(e)
	}
	if e := a.Store.DecideNetwork(admin, gid, version, targetVersion, "Approved", time.Now().Add(48*time.Hour).Format("2006-01-02"), "Reviewed connection", true); e != nil {
		t.Fatal(e)
	}
	ackPack(t, a)
}
func ackPack(t *testing.T, a *App) {
	t.Helper()
	snapshot, e := a.Store.VPNSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Store.DB.Exec("UPDATE vpn_status SET revision=?,public_key=?,seen=? WHERE id=1", snapshot.Revision, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), now()); e != nil {
		t.Fatal(e)
	}
}
func packPrivate(t *testing.T, pack []byte, id int) string {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(pack), int64(len(pack)))
	if e != nil {
		t.Fatal(e)
	}
	if len(z.File) != 2 {
		t.Fatal("unexpected ZIP entries")
	}
	var conf string
	for _, f := range z.File {
		if f.Mode().Perm() != 0600 {
			t.Fatal("unsafe ZIP permissions")
		}
		if f.Name == fmt.Sprintf("wp%d.conf", id) {
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			conf = string(b)
		} else if f.Name != "READ-ME.txt" {
			t.Fatal("unsafe ZIP filename")
		}
	}
	if !strings.Contains(conf, "AllowedIPs = 192.0.2.23/32") || strings.Contains(conf, "PostUp") || !strings.Contains(conf, "MTU = 1280") {
		t.Fatal("wrong connection settings")
	}
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			return strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	t.Fatal("missing private key")
	return ""
}
func TestPackOwnerOneTimeAndNoSecretPayloads(t *testing.T) {
	a, admin, alice, bob, id := packFixture(t)
	if _, e := a.consumePack(alice, id); e == nil {
		t.Fatal("pending device downloaded")
	}
	approvePack(t, a, admin, id)
	for _, u := range []*User{admin, bob} {
		if _, e := a.consumePack(u, id); e == nil {
			t.Fatal("non-owner downloaded")
		}
	}
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := loginClient(t, server, alice.Username)
	body, _ := get(t, c, server.URL+"/my-devices")
	if !strings.Contains(body, "Download connection pack") {
		t.Fatal("ready pack button missing")
	}
	path := fmt.Sprintf("/my-devices/%d/pack", id)
	req, _ := http.NewRequest("POST", server.URL+path, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("missing CSRF accepted", res.StatusCode)
	}
	_, code := get(t, c, server.URL+path)
	if code != 404 && code != 405 {
		t.Fatal("GET delivers secret")
	}
	data := url.Values{"gorilla.csrf.Token": {csrfRE.FindStringSubmatch(body)[1]}}
	req, _ = http.NewRequest("POST", server.URL+path, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", server.URL)
	res, e = c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	pack, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || res.StatusCode != 200 {
		t.Fatal("download failed", res.StatusCode, e)
	}
	if res.Header.Get("Content-Type") != "application/zip" || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("unsafe download headers")
	}
	secret := packPrivate(t, pack, id)
	raw, e := base64.StdEncoding.DecodeString(secret)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdh.X25519().NewPrivateKey(raw)
	if e != nil {
		t.Fatal(e)
	}
	var pub string
	a.Store.DB.QueryRow("SELECT public_key FROM vpn_devices WHERE id=?", id).Scan(&pub)
	if base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != pub {
		t.Fatal("key mismatch")
	}
	if count(t, a.Store, "SELECT count(*) FROM vpn_deliveries WHERE device_id=? AND encrypted_key IS NULL AND consumed IS NOT NULL", id) != 1 {
		t.Fatal("secret retained")
	}
	if _, e = a.consumePack(alice, id); e == nil {
		t.Fatal("download repeated")
	}
	for _, path := range []string{"/my-devices", "/notifications", "/"} {
		body, _ = get(t, c, server.URL+path)
		if strings.Contains(body, secret) {
			t.Fatal("private key in HTML")
		}
	}
	var logged string
	a.Store.DB.QueryRow("SELECT coalesce(group_concat(text),'') FROM notifications").Scan(&logged)
	if strings.Contains(logged, secret) {
		t.Fatal("secret in notifications")
	}
	snapshot, _ := a.Store.VPNSnapshot()
	if strings.Contains(fmt.Sprint(snapshot), secret) {
		t.Fatal("secret in gateway policy")
	}
}
func TestPackConcurrencyAndReplacement(t *testing.T) {
	a, admin, alice, _, id := packFixture(t)
	approvePack(t, a, admin, id)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := a.consumePack(alice, id); results <- e }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("multiple deliveries", successes)
	}
	var version int
	var pub string
	a.Store.DB.QueryRow("SELECT version,public_key FROM vpn_devices WHERE id=?", id).Scan(&version, &pub)
	if _, e := a.createPackDevice(alice, "Simple laptop", 1, "Lost my pack", id, version, false); e == nil {
		t.Fatal("unconfirmed replacement")
	}
	newID, e := a.createPackDevice(alice, "Simple laptop", 1, "Lost my pack", id, version, true)
	if e != nil {
		t.Fatal(e)
	}
	var newPub string
	a.Store.DB.QueryRow("SELECT public_key FROM vpn_devices WHERE id=?", newID).Scan(&newPub)
	if pub == newPub || id == newID {
		t.Fatal("identity reused")
	}
	if count(t, a.Store, "SELECT count(*) FROM vpn_devices WHERE id=? AND state='revoked'", id) != 1 || count(t, a.Store, "SELECT count(*) FROM vpn_grants WHERE device_id=? AND state='Pending'", newID) != 1 {
		t.Fatal("replacement bypassed approval")
	}
	if _, e = a.consumePack(alice, newID); e == nil {
		t.Fatal("replacement downloaded without approval")
	}
	if _, e = a.createPackDevice(alice, "Simple laptop", 1, "Retry old form", id, version, true); e == nil {
		t.Fatal("stale replacement accepted")
	}
	results = make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := a.createPackDevice(alice, "Second computer", 1, "Duplicate submission", 0, 0, false)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	successes = 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("duplicate devices", successes)
	}
}
func TestPackExpiryVisibilityAndInvalidation(t *testing.T) {
	cases := map[string]string{
		"delivery expiry":          "UPDATE vpn_deliveries SET expires='2000-01-01T00:00:00Z'",
		"grant expiry":             "UPDATE vpn_grants SET expires='2000-01-01T00:00:00Z'",
		"disabled member":          "UPDATE users SET enabled=0 WHERE username='alice'",
		"invalidated session":      "UPDATE users SET generation=generation+1 WHERE username='alice'",
		"revoked device":           "UPDATE vpn_devices SET state='revoked'",
		"revoked grant":            "UPDATE vpn_grants SET state='Revoked'",
		"disabled target":          "UPDATE vpn_targets SET enabled=0",
		"unpublished service":      "UPDATE services SET published=0",
		"private service":          "UPDATE services SET audience='admin'",
		"grant restricted service": "UPDATE services SET audience='access'",
		"private category":         "UPDATE categories SET audience='admin'",
		"stale acknowledgment":     "UPDATE vpn_status SET seen='2000-01-01T00:00:00Z'",
		"wrong revision":           "UPDATE vpn_status SET revision='wrong'",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			a, admin, alice, _, id := packFixture(t)
			approvePack(t, a, admin, id)
			if _, e := a.Store.DB.Exec(q); e != nil {
				t.Fatal(e)
			}
			// Fresh ack for changed desired policy must not bypass audience/expiry checks.
			if name != "stale acknowledgment" && name != "wrong revision" {
				ackPack(t, a)
			}
			if _, e := a.consumePack(alice, id); e == nil {
				t.Fatal("invalid pack delivered")
			}
			if count(t, a.Store, "SELECT count(*) FROM vpn_deliveries WHERE consumed IS NOT NULL") != 0 {
				t.Fatal("failed download consumed")
			}
		})
	}
}
func TestPackEncryptionRestartTamperAndRollback(t *testing.T) {
	a, admin, alice, _, id := packFixture(t)
	approvePack(t, a, admin, id)
	var ciphertext []byte
	var pub string
	a.Store.DB.QueryRow("SELECT encrypted_key FROM vpn_deliveries WHERE device_id=?", id).Scan(&ciphertext)
	a.Store.DB.QueryRow("SELECT public_key FROM vpn_devices WHERE id=?", id).Scan(&pub)
	if len(ciphertext) <= 32 {
		t.Fatal("plaintext private material")
	}
	plain, e := a.deliveryCipher.Open(nil, nil, ciphertext, deliveryAAD(alice.ID, id, pub))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(ciphertext, plain) {
		t.Fatal("plaintext in stored ciphertext")
	}
	if _, e = a.deliveryCipher.Open(nil, nil, ciphertext, deliveryAAD(alice.ID, id+1, pub)); e == nil {
		t.Fatal("unbound device identity")
	}
	changed := bytes.Clone(ciphertext)
	changed[0] ^= 1
	a.Store.DB.Exec("UPDATE vpn_deliveries SET encrypted_key=? WHERE device_id=?", changed, id)
	if _, e = a.consumePack(alice, id); e == nil {
		t.Fatal("tampering accepted")
	}
	a.Store.DB.Exec("UPDATE vpn_deliveries SET encrypted_key=? WHERE device_id=?", ciphertext, id)
	a.Config.VPNEndpoint = "invalid\nPostUp = command"
	if _, e = a.consumePack(alice, id); e == nil {
		t.Fatal("invalid settings accepted")
	}
	if count(t, a.Store, "SELECT count(*) FROM vpn_deliveries WHERE encrypted_key IS NOT NULL AND consumed IS NULL") != 1 {
		t.Fatal("failed build lost pack")
	}
	a.Config.VPNEndpoint = "vpn.example.invalid:51820"
	restarted, e := New(a.Store, a.Config, web.Assets)
	if e != nil {
		t.Fatal(e)
	}
	pack, e := restarted.consumePack(alice, id)
	if e != nil {
		t.Fatal(e)
	}
	if packPrivate(t, pack, id) != base64.StdEncoding.EncodeToString(plain) {
		t.Fatal("restart changed key")
	}
	// A missing key must fail closed while pending encrypted deliveries exist.
	_, e = a.createPackDevice(alice, "Other phone", 1, "Second connection", 0, 0, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(a.Config.VPNDeliveryDir, "delivery.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = New(a.Store, a.Config, web.Assets); e == nil {
		t.Fatal("lost encryption key silently replaced")
	}
}
func TestPackMigrationFromV2(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "old.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Write(func(tx *sql.Tx) error {
		for _, q := range []string{schema, vpnSchema, "CREATE TABLE migrations(version INTEGER PRIMARY KEY)", "INSERT INTO migrations VALUES(1),(2)"} {
			if _, e := tx.Exec(q); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.CreateAdmin("old-owner", "old password long enough"); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT max(version) FROM migrations") != len(schemaMigrations) || count(t, s, "SELECT count(*) FROM users WHERE username='old-owner'") != 1 {
		t.Fatal("migration lost existing data")
	}
}

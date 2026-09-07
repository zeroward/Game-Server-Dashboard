package portal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"waypoint/internal/vpn"
)

func vpnFixture(t *testing.T) (*App, *User, *User, *User, NetworkTarget) {
	a, admin, alice, bob := fixture(t)
	a.Config.VPNEnabled = true
	a.Config.VPNEndpoint = "vpn.example.invalid:51820"
	service := serviceNamed(t, a.Store, "development-network")
	target := NetworkTarget{ServiceID: service.ID, Label: "Developer workspace", CIDR: "192.0.2.23/32", Protocol: "tcp", Ports: "443", Enabled: true}
	if e := a.Store.SaveNetworkTarget(admin, target); e != nil {
		t.Fatal(e)
	}
	targets, _ := a.Store.VPNTargets()
	target = targets[0]
	for i, u := range []*User{alice, bob} {
		if e := a.Store.EnrollDevice(u, u.Username+" laptop", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 5)}, 32))); e != nil {
			t.Fatal(e)
		}
	}
	return a, admin, alice, bob, target
}
func TestVPNApprovalOwnershipAndVisibility(t *testing.T) {
	a, admin, alice, bob, target := vpnFixture(t)
	s := a.Store
	if e := s.RequestNetwork(bob, 1, target.ID, "Trying another member device"); e == nil {
		t.Fatal("cross-member request")
	}
	if e := s.RequestNetwork(alice, 1, target.ID, "Development work"); e != nil {
		t.Fatal(e)
	}
	if e := s.DecideNetwork(alice, 1, 1, 1, "Approved", time.Now().Add(48*time.Hour).Format("2006-01-02"), "setup ready", true); e == nil {
		t.Fatal("member escalated")
	}
	before, _ := s.VPNSnapshot()
	if len(before.Peers) != 0 {
		t.Fatal("pending grants activated")
	}
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	ca := loginClient(t, server, alice.Username)
	cb := loginClient(t, server, bob.Username)
	body, code := get(t, ca, server.URL+"/my-devices")
	if code != 200 {
		t.Fatal(code)
	}
	assertNo(t, body, target.CIDR, "bob laptop")
	body, _ = get(t, cb, server.URL+"/my-devices")
	assertNo(t, body, "alice laptop", "Development work")
	_, code = get(t, ca, server.URL+"/admin/vpn")
	if code != 403 {
		t.Fatal("member admin route", code)
	}
	deadline := time.Now().Add(48 * time.Hour).Format("2006-01-02")
	if e := s.DecideNetwork(admin, 1, 1, 1, "Approved", deadline, "Explicit network approval", false); e == nil {
		t.Fatal("no confirmation")
	}
	if e := s.DecideNetwork(admin, 1, 1, 1, "Approved", deadline, "Explicit network approval", true); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM access_records") != 0 {
		t.Fatal("network approval created external access record")
	}
	after, e := s.VPNSnapshot()
	if e != nil || len(after.Peers) != 1 {
		t.Fatal(e, after)
	}
	body, _ = get(t, ca, server.URL+"/my-devices")
	if !strings.Contains(body, target.CIDR) {
		t.Fatal("approved setup unavailable")
	}
	if s.RevokeDevice(bob, 1, 2) == nil {
		t.Fatal("cross-member revoke")
	}
	if e = s.RevokeDevice(alice, 1, 2); e != nil {
		t.Fatal(e)
	}
	after, _ = s.VPNSnapshot()
	if len(after.Peers) != 0 {
		t.Fatal("revoked peer remains")
	}
	body, _ = get(t, ca, server.URL+"/my-devices")
	assertNo(t, body, target.CIDR)
}
func TestVPNConflictsExpiryTargetsAndArchive(t *testing.T) {
	a, admin, alice, _, target := vpnFixture(t)
	s := a.Store
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.RequestNetwork(alice, 1, target.ID, "Concurrency check") }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("duplicate active requests", success)
	}
	target.Ports = "8443"
	if e := s.SaveNetworkTarget(admin, target); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(48 * time.Hour).Format("2006-01-02")
	if s.DecideNetwork(admin, 1, 1, 1, "Approved", deadline, "Stale target review", true) == nil {
		t.Fatal("stale target approved")
	}
	if e := s.DecideNetwork(admin, 1, 1, 2, "Approved", deadline, "Reviewed changed target", true); e != nil {
		t.Fatal(e)
	}
	if s.DecideNetwork(admin, 1, 1, 2, "Denied", "", "Conflicting decision", true) == nil {
		t.Fatal("conflicting decision accepted")
	}
	target.Version = 2
	target.Ports = "9443"
	if e := s.SaveNetworkTarget(admin, target); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.VPNSnapshot()
	if snap.Peers[0].Rules[0].Ports != "8443" {
		t.Fatal("target edit expanded approved grant")
	}
	s.DB.Exec("UPDATE users SET enabled=0 WHERE id=?", alice.ID)
	snap, _ = s.VPNSnapshot()
	if len(snap.Peers) != 0 {
		t.Fatal("disabled user retained")
	}
	s.DB.Exec("UPDATE users SET enabled=1 WHERE id=?", alice.ID)
	s.DB.Exec("UPDATE vpn_grants SET expires=?", stamp(time.Now().Add(-time.Second)))
	snap, _ = s.VPNSnapshot()
	if len(snap.Peers) != 0 {
		t.Fatal("expired permissions retained")
	}
	if e := s.RequestNetwork(alice, 1, target.ID, "Renew access after expiry"); e != nil {
		t.Fatal(e)
	}
	if e := a.destroyService(admin, target.ServiceID, "delete", true); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM services WHERE id=? AND archived=1", target.ServiceID) != 1 {
		t.Fatal("network history not archived")
	}
}
func TestVPNControlPrivacyCSRFAndNotifications(t *testing.T) {
	a, admin, alice, bob, target := vpnFixture(t)
	s := a.Store
	s.RequestNetwork(alice, 1, target.ID, "My private intended use")
	token := strings.Repeat("e", 64)
	h := a.VPNControlHandler(token)
	req := httptest.NewRequest("GET", "/v1/policy", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("unauthenticated control")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	assertNo(t, w.Body.String(), "alice", "private intended", target.CIDR)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, alice.Username)
	res, e := client.PostForm(server.URL+"/my-devices", url.Values{"action": {"revoke"}, "device": {"1"}, "version": {"1"}, "confirm": {"yes"}})
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("missing CSRF accepted")
	}
	s.DecideNetwork(admin, 1, 1, 1, "Approved", time.Now().Add(48*time.Hour).Format("2006-01-02"), "Approved for work", true)
	if len(a.visibleNotifications(bob, false)) != 0 {
		t.Fatal("notification leaked")
	}
	if len(a.visibleNotifications(alice, false)) == 0 {
		t.Fatal("notification missing")
	}
	snap, _ := s.VPNSnapshot()
	payload, _ := json.Marshal(vpn.Ack{Revision: snap.Revision, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))})
	req = httptest.NewRequest("POST", "/v1/applied", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.DB.Exec("UPDATE vpn_targets SET enabled=0")
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/v1/applied", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatal("stale ack accepted")
	}
	body, _ := get(t, client, server.URL+"/my-devices")
	assertNo(t, body, target.CIDR)
	a.Config.VPNEnabled = false
	body, code := get(t, client, server.URL+"/my-devices")
	if code != 404 {
		t.Fatal("disabled feature route", code)
	}
	assertNo(t, body, target.CIDR)
}

func TestVPNMigrationPreservesVersionOneData(t *testing.T) {
	s, e := Open(t.TempDir() + "/previous.db")
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if _, e = s.DB.Exec(schema); e != nil {
		t.Fatal(e)
	}
	s.DB.Exec("CREATE TABLE migrations(version INTEGER PRIMARY KEY)")
	s.DB.Exec("INSERT INTO migrations VALUES(1)")
	s.DB.Exec("UPDATE settings SET name='Existing community' WHERE id=1")
	s.DB.Exec("INSERT INTO users(username,password,role,created) VALUES('existing-owner','test-only-unused-hash','admin',?)", now())
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if s.Settings().Name != "Existing community" || s.User(1).Username != "existing-owner" {
		t.Fatal("migration changed existing data")
	}
	if count(t, s, "SELECT max(version) FROM migrations") != 3 {
		t.Fatal("migration missing")
	}
	if _, e = s.VPNSnapshot(); e != nil {
		t.Fatal(e)
	}
}
func TestVPNHiddenOfferingDisableAndHistory(t *testing.T) {
	a, admin, alice, _, target := vpnFixture(t)
	s := a.Store
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, alice.Username)
	s.DB.Exec("UPDATE services SET audience='admin' WHERE id=?", target.ServiceID)
	body, _ := get(t, client, server.URL+"/my-devices")
	assertNo(t, body, "Developer workspace", target.CIDR)
	if s.RequestNetwork(alice, 1, target.ID, "Guessing a hidden destination") == nil {
		t.Fatal("hidden offering requested")
	}
	s.DB.Exec("UPDATE services SET audience='member' WHERE id=?", target.ServiceID)
	if e := s.RequestNetwork(alice, 1, target.ID, "Approved development"); e != nil {
		t.Fatal(e)
	}
	if e := s.DecideNetwork(admin, 1, 1, 1, "Approved", time.Now().Add(48*time.Hour).Format("2006-01-02"), "Reviewed device and endpoint", true); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM vpn_history WHERE state='Approved' AND cidr=?", target.CIDR) != 1 {
		t.Fatal("reviewed rule audit missing")
	}
	if e := a.saveMember(admin, alice.ID, formRequest(url.Values{"role": {"member"}, "confirm": {"on"}})); e != nil {
		t.Fatal(e)
	}
	if e := a.saveMember(admin, alice.ID, formRequest(url.Values{"role": {"member"}, "enabled": {"on"}, "confirm": {"on"}})); e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.VPNSnapshot()
	if e != nil || len(snapshot.Peers) != 0 {
		t.Fatal("reenabling member restored network grants")
	}
	if count(t, s, "SELECT count(*) FROM vpn_history WHERE state='Revoked' AND cidr=?", target.CIDR) != 1 {
		t.Fatal("disablement audit lost reviewed route")
	}
	_, code := get(t, client, server.URL+"/my-devices")
	if code != 200 {
		t.Fatal(code)
	} // old session now sees login after redirect
	body, _ = get(t, client, server.URL+"/my-devices")
	assertNo(t, body, "alice laptop", target.CIDR)
}
func TestVPNExpiryAuditAndTargetMutationHTTP(t *testing.T) {
	a, admin, alice, _, target := vpnFixture(t)
	s := a.Store
	s.RequestNetwork(alice, 1, target.ID, "Short lived project")
	s.DecideNetwork(admin, 1, 1, 1, "Approved", time.Now().Add(48*time.Hour).Format("2006-01-02"), "Reviewed access", true)
	s.DB.Exec("UPDATE vpn_grants SET expires=? WHERE id=1", stamp(time.Now().Add(-time.Second)))
	if e := s.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if e := s.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM vpn_history WHERE state='Expired'") != 1 {
		t.Fatal("expiry audit duplicated or missing")
	}
	if count(t, s, "SELECT count(*) FROM vpn_grants WHERE state='Expired'") != 1 {
		t.Fatal("expiry state missing")
	}
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	owner := loginClient(t, server, admin.Username)
	member := loginClient(t, server, alice.Username)
	values := url.Values{"action": {"target"}, "id": {"1"}, "version": {"1"}, "service": {fmt.Sprint(target.ServiceID)}, "label": {"Changed label"}, "cidr": {target.CIDR}, "protocol": {"tcp"}, "ports": {"443"}, "enabled": {"yes"}, "confirm": {"yes"}}
	_, code := post(t, member, server.URL, "/my-devices", values)
	if code != 400 {
		t.Fatal("member target mutation accepted", code)
	}
	values.Del("confirm")
	_, code = post(t, owner, server.URL, "/admin/vpn", values)
	if code != 400 {
		t.Fatal("unconfirmed target edit", code)
	}
	values.Set("confirm", "yes")
	_, code = post(t, owner, server.URL, "/admin/vpn", values)
	if code != 200 {
		t.Fatal("target edit failed", code)
	}
	body, code := get(t, member, server.URL+"/v1/policy")
	if code != 404 {
		t.Fatal("control API exposed on browser listener")
	}
	assertNo(t, body, target.CIDR)
	if count(t, s, "SELECT count(*) FROM access_records") != 0 {
		t.Fatal("expiry created external records")
	}
}

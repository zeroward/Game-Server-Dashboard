package portal

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/pquerna/otp/totp"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"waypoint/web"
)

func fixture(t *testing.T) (*App, *User, *User, *User) {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "uploads"), 0700)
	s, e := Open(filepath.Join(dir, "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if e = s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if e = s.CreateAdmin("owner", "a long test password"); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"alice", "bob"} {
		token, e := s.IssueToken(1, "invite", name, "", 0)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Redeem(token, "a long test password"); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.SeedDemo(); e != nil {
		t.Fatal(e)
	}
	a, e := New(s, Config{DataDir: dir, BaseURL: "http://localhost:8080"}, web.Assets)
	if e != nil {
		t.Fatal(e)
	}
	return a, s.User(1), s.User(2), s.User(3)
}
func serviceNamed(t *testing.T, s *Store, slug string) *Service {
	t.Helper()
	for _, v := range s.AllServices() {
		if v.Slug == slug {
			return &v
		}
	}
	t.Fatal("missing service " + slug)
	return nil
}
func setConfig(t *testing.T, s *Store, v *Service) {
	t.Helper()
	b, _ := json.Marshal(v.Config)
	if _, e := s.DB.Exec("UPDATE services SET config=? WHERE id=?", string(b), v.ID); e != nil {
		t.Fatal(e)
	}
}
func assertNo(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(body, secret) {
			t.Errorf("restricted value leaked: %q", secret)
		}
	}
}
func count(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if e := s.DB.QueryRow(q, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestInvitationsRecoveryAndRoles(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	token, e := s.IssueToken(admin.ID, "invite", "carol", "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if n := count(t, s, "SELECT count(*) FROM tokens WHERE hash=?", token); n != 0 {
		t.Fatal("raw token stored")
	}
	if e = s.Redeem(token, "a long test password"); e != nil {
		t.Fatal(e)
	}
	if e = s.Redeem(token, "a different password"); e == nil {
		t.Fatal("reused invitation")
	}
	var role string
	s.DB.QueryRow("SELECT role FROM users WHERE username='carol'").Scan(&role)
	if role != "member" {
		t.Fatal("invitation escalated role")
	}
	if count(t, s, "SELECT count(*) FROM access_records") != 0 {
		t.Fatal("invite granted access")
	}
	token, _ = s.IssueToken(admin.ID, "invite", "expired", "", 0)
	s.DB.Exec("UPDATE tokens SET expires=? WHERE hash=?", stamp(time.Now().Add(-time.Minute)), hashToken(token))
	if s.Redeem(token, "a long test password") == nil {
		t.Fatal("expired token accepted")
	}
	token, _ = s.IssueToken(admin.ID, "reset", "", "", alice.ID)
	before := alice.Generation
	if e = s.Redeem(token, "a changed test password"); e != nil {
		t.Fatal(e)
	}
	if s.User(alice.ID).Generation <= before {
		t.Fatal("reset did not invalidate sessions")
	}
	if s.Redeem(token, "a changed test password") == nil {
		t.Fatal("reset reuse accepted")
	}
	if e = s.CreateAdmin("another", "a long test password"); e == nil {
		t.Fatal("second bootstrap allowed")
	}
	if e = s.Recover("owner", "a recovered password"); e != nil {
		t.Fatal(e)
	}
	r := formRequest(url.Values{"role": {"member"}, "confirm": {"on"}, "enabled": {"on"}})
	if e = a.saveMember(admin, admin.ID, r); e == nil {
		t.Fatal("last admin demoted")
	}
	r = formRequest(url.Values{"role": {"admin"}, "confirm": {"on"}})
	if e = a.saveMember(admin, admin.ID, r); e == nil {
		t.Fatal("last admin disabled")
	}
}
func TestConcurrentInvitationRedemption(t *testing.T) {
	a, admin, _, _ := fixture(t)
	token, _ := a.Store.IssueToken(admin.ID, "invite", "onlyonce", "", 0)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- a.Store.Redeem(token, "a long test password") }()
	}
	wg.Wait()
	close(results)
	ok := 0
	for e := range results {
		if e == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d redemptions succeeded", ok)
	}
}
func TestVisibilityLinksSearchAndMedia(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "development-network")
	v.Config.Host = "private-host.invalid"
	v.Config.Connection = "private-connection-marker"
	v.Config.Guide = "private-guide-marker"
	setConfig(t, s, v)
	permitted := s.permitted(alice, *v)
	if permitted == nil || permitted.Details {
		t.Fatal("discovery and details not separate")
	}
	b, _ := json.Marshal(permitted)
	assertNo(t, string(b), "private-host.invalid", "private-connection-marker", "private-guide-marker")
	s.DB.Exec("INSERT INTO links(label,url,placement,parent_id,access_service,audience,enabled) VALUES('restricted','https://private-link.invalid','global',NULL,?,'access',1)", v.ID)
	if len(s.LinksFor(alice, "global", 0)) != 0 {
		t.Fatal("pending member sees restricted global link")
	}
	s.DB.Exec("UPDATE settings SET public=1")
	s.DB.Exec("INSERT INTO links(label,url,placement,parent_id,audience,enabled) VALUES('child','https://private-parent.invalid','service',?,'public',1)", v.ID)
	if len(s.LinksFor(nil, "service", v.ID)) != 0 {
		t.Fatal("public child bypasses member parent")
	}
	s.DB.Exec("UPDATE services SET audience='admin' WHERE id=?", v.ID)
	s.DB.Exec("INSERT INTO links(label,url,placement,access_service,audience,enabled) VALUES('hidden-reference','https://secret.invalid','global',?,'public',1)", v.ID)
	if len(s.LinksFor(alice, "global", 0)) != 0 {
		t.Fatal("associated hidden service leaked")
	}
	s.DB.Exec("INSERT INTO media(id,service_id,filename,created) VALUES('secret-art',?,'secret.jpg',?)", v.ID, now())
	os.WriteFile(filepath.Join(a.Config.DataDir, "uploads", "secret.jpg"), []byte("SECRET IMAGE BYTES"), 0600)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, "alice")
	body, status := get(t, client, server.URL+"/?q=Development")
	if status != 200 {
		t.Fatal(status)
	}
	assertNo(t, body, "Development Network", "private-host.invalid")
	body, status = get(t, client, server.URL+"/services/development-network")
	if status != 404 {
		t.Fatal("hidden service direct route", status)
	}
	assertNo(t, body, "private-guide-marker")
	body, status = get(t, client, server.URL+"/media/secret-art")
	if status != 404 {
		t.Fatal("private media exposed", status)
	}
	assertNo(t, body, "SECRET IMAGE BYTES")
	s.DB.Exec("UPDATE services SET audience='member' WHERE id=?", v.ID)
	if e := s.Write(func(tx *sql.Tx) error { _, e := grant(tx, admin.ID, alice.ID, v.ID, "safe steps", ""); return e }); e != nil {
		t.Fatal(e)
	}
	if !s.permitted(alice, *v).Details {
		t.Fatal("active record does not unlock details")
	}
	s.DB.Exec("UPDATE services SET published=0 WHERE id=?", v.ID)
	if len(s.LinksFor(alice, "global", 0)) != 0 {
		t.Fatal("unpublished associated parent leaked")
	}
}
func TestAccessLifecycleAndSupport(t *testing.T) {
	a, admin, alice, bob := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "development-network")
	id, e := s.Submit(alice, v, "access", "Please let me develop", "", map[string]string{"f0": "Laptop", "f1": "Learning"})
	if e != nil {
		t.Fatal(e)
	}
	if s.request(bob, id) != nil {
		t.Fatal("other member can read request")
	}
	if s.hasAccess(alice, v.ID) {
		t.Fatal("submission granted access")
	}
	if _, e = s.Submit(alice, v, "access", "duplicate", "", map[string]string{"f0": "Laptop", "f1": "Learning"}); e == nil {
		t.Fatal("duplicate allowed")
	}
	if e = s.Reply(bob, id, 1, "read me", false); e == nil {
		t.Fatal("other member replied")
	}
	if e = s.Reply(alice, id, 1, "private", true); e == nil {
		t.Fatal("member wrote private note")
	}
	if e = s.Transition(admin, id, 1, "Fulfilled", "", "steps", "", true); e == nil {
		t.Fatal("skipped approval")
	}
	if e = s.Transition(admin, id, 1, "Needs Information", "", "", "", false); e == nil {
		t.Fatal("missing explanation accepted")
	}
	if e = s.Transition(admin, id, 1, "Needs Information", "What client?", "", "", false); e != nil {
		t.Fatal(e)
	}
	if e = s.Reply(alice, id, 2, "Here is the client", false); e != nil {
		t.Fatal(e)
	}
	r := s.request(alice, id)
	if r.State != "Pending" {
		t.Fatal("reply did not return to review")
	}
	if e = s.Transition(admin, id, r.Version, "Approved - Setup Pending", "", "", "", false); e != nil {
		t.Fatal(e)
	}
	if s.hasAccess(alice, v.ID) {
		t.Fatal("approval granted access")
	}
	r = s.request(alice, id)
	if e = s.Transition(admin, id, r.Version, "Fulfilled", "", "steps", "", false); e == nil {
		t.Fatal("fulfillment without confirmation")
	}
	if e = s.Transition(admin, id, r.Version, "Fulfilled", "", "", "", true); e == nil {
		t.Fatal("fulfillment without next steps")
	}
	if e = s.Transition(admin, id, r.Version, "Fulfilled", "", "Use your separately configured client.", "", true); e != nil {
		t.Fatal(e)
	}
	if !s.hasAccess(alice, v.ID) {
		t.Fatal("fulfillment did not grant")
	}
	if e = s.Transition(admin, id, r.Version, "Fulfilled", "", "steps", "", true); e == nil {
		t.Fatal("duplicate fulfillment")
	}
	if count(t, s, "SELECT count(*) FROM access_records WHERE user_id=? AND service_id=?", alice.ID, v.ID) != 1 {
		t.Fatal("duplicate access records")
	}
	support, e := s.Submit(bob, v, "support", "Cannot connect", "", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Transition(admin, support, 1, "Resolved", "Try the specified client", "", "", false); e != nil {
		t.Fatal(e)
	}
	if s.hasAccess(bob, v.ID) {
		t.Fatal("support resolution granted access")
	}
}
func TestConcurrentRequestsAndFulfillment(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "plex")
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, e := s.Submit(alice, v, "access", "Media access please", "", map[string]string{"f0": "test@example.invalid"})
			if e == nil {
				results <- id
			}
		}()
	}
	wg.Wait()
	close(results)
	ids := []int{}
	for id := range results {
		ids = append(ids, id)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d submissions", len(ids))
	}
	id := ids[0]
	if e := s.Transition(admin, id, 1, "Approved - Setup Pending", "", "", "", false); e != nil {
		t.Fatal(e)
	}
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Transition(admin, id, 2, "Fulfilled", "", "Accept the external invitation", "", true)
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for e := range errs {
		if e == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("got %d fulfillment successes", ok)
	}
}
func TestExpiryRevocationDisableAndHistory(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "development-network")
	e := s.Write(func(tx *sql.Tx) error {
		_, e := grant(tx, admin.ID, alice.ID, v.ID, "sensitive-next-steps", stamp(time.Now().Add(-time.Second)))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if s.hasAccess(alice, v.ID) {
		t.Fatal("expired access unlocks content")
	}
	if s.permitted(alice, *v).Details {
		t.Fatal("expired details unlocked")
	}
	if strings.Contains(fmt.Sprint(s.Accesses(alice)), "sensitive-next-steps") {
		t.Fatal("expired next steps exposed")
	}
	if e = s.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM followups WHERE completed IS NULL") != 1 {
		t.Fatal("no expiry followup")
	}
	s.Reconcile()
	if count(t, s, "SELECT count(*) FROM followups") != 1 {
		t.Fatal("duplicate followup")
	}
	e = s.Write(func(tx *sql.Tx) error { _, e := grant(tx, admin.ID, alice.ID, v.ID, "steps", ""); return e })
	if e != nil {
		t.Fatal(e)
	}
	r := formRequest(url.Values{"role": {"member"}, "confirm": {"on"}})
	if e = a.saveMember(admin, alice.ID, r); e != nil {
		t.Fatal(e)
	}
	if s.hasAccess(s.User(alice.ID), v.ID) {
		t.Fatal("disabled access unlocked")
	}
	if count(t, s, "SELECT count(*) FROM access_records WHERE state='revoked'") != 1 {
		t.Fatal("disable did not revoke portal records")
	}
	if e = a.destroyService(admin, v.ID, "delete", true); e != nil {
		t.Fatal(e)
	}
	if s.service(v.ID) == nil || !s.service(v.ID).Archived {
		t.Fatal("historical service deleted")
	}
}
func TestPrivateNotesAndNotificationsHTTP(t *testing.T) {
	a, admin, alice, bob := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "campfire")
	id, e := s.Submit(alice, v, "support", "Need help joining", "", nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Reply(admin, id, 1, "ADMIN_PRIVATE_SENTINEL", true)
	s.Reply(admin, id, 2, "Member visible response", false)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, "alice")
	body, status := get(t, client, fmt.Sprintf("%s/requests/%d", server.URL, id))
	if status != 200 {
		t.Fatal(status, body)
	}
	assertNo(t, body, "ADMIN_PRIVATE_SENTINEL")
	if !strings.Contains(body, "Member visible response") {
		t.Fatal("public reply missing")
	}
	body, status = get(t, client, server.URL+"/notifications")
	if status != 200 {
		t.Fatal(status)
	}
	assertNo(t, body, "ADMIN_PRIVATE_SENTINEL", "Member visible response")
	other := loginClient(t, server, bob.Username)
	body, status = get(t, other, fmt.Sprintf("%s/requests/%d", server.URL, id))
	if status != 404 {
		t.Fatal("cross-owner read", status)
	}
	assertNo(t, body, "Need help joining", "Member visible response")
	body, status = get(t, other, server.URL+"/admin/audit")
	if status != 403 {
		t.Fatal("member admin access", status)
	}
	assertNo(t, body, "private note")
	if len(a.visibleNotifications(bob, false)) != 0 {
		t.Fatal("other user's notifications visible")
	}
}
func TestDirectCardsAndCaches(t *testing.T) {
	a, _, alice, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "development-network")
	res, e := s.DB.Exec("INSERT INTO links(label,url,placement,parent_id,access_service,audience,enabled) VALUES('Open Secret','https://private-destination.invalid','service',?,?,'access',1)", v.ID, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	n, _ := res.LastInsertId()
	v.Config.DirectLink = int(n)
	setConfig(t, s, v)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, alice.Username)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Get(server.URL + "/services/development-network/open")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.Header.Get("Location") != "/services/development-network" {
		t.Fatal("protected direct destination redirect", resp.Header.Get("Location"))
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("cache leak risk")
	}
	body, status := get(t, client, server.URL+"/services/development-network")
	if status != 200 {
		t.Fatal(status)
	}
	assertNo(t, body, "private-destination.invalid", "Open Secret")
	_, status = get(t, client, fmt.Sprintf("%s/out/%d", server.URL, n))
	if status != 404 {
		t.Fatal("out route leaks", status)
	}
}
func TestInputValidationAndMarkdown(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,hello", "https://user:pass@host/path", "//example.com", "https://good.invalid\nHeader: yes", "file:///etc/passwd", "ftp://host/path", "steam://run/1"} {
		if validURL(raw, false) == nil {
			t.Errorf("accepted bad URL %q", raw)
		}
	}
	for _, raw := range []string{"https://plex.internal:32400/web", "http://192.0.2.1:80", "http://[2001:db8::1]:8080", "https://example.invalid"} {
		if e := validURL(raw, false); e != nil {
			t.Errorf("rejected valid URL %q: %v", raw, e)
		}
	}
	if validURL("steam://run/123", true) != nil {
		t.Fatal("explicit supported launch rejected")
	}
	rendered := string(markdown("<script>alert('x')</script>\n\n[x](javascript:alert(1))\n\n![tracking](https://tracker.invalid/pixel)\n\n**safe**"))
	assertNo(t, rendered, "<script", "javascript:", "<img", "tracker.invalid")
	if !strings.Contains(rendered, "<strong>safe</strong>") {
		t.Fatal("Markdown lost safe content")
	}
	for _, b := range [][]byte{[]byte("<svg onload='alert(1)'></svg>"), []byte("<html>oops</html>"), []byte("not an image"), make([]byte, (8<<20)+1)} {
		if _, e := decodeArtwork(b); e == nil {
			t.Fatal("invalid image accepted")
		}
	}
	var b bytes.Buffer
	png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 30, 20)))
	if _, e := decodeArtwork(b.Bytes()); e != nil {
		t.Fatal(e)
	}
	b.Reset()
	png.Encode(&b, image.NewGray(image.Rect(0, 0, 5000, 5000)))
	if _, e := decodeArtwork(b.Bytes()); e == nil {
		t.Fatal("oversized decoded dimensions accepted")
	}
}
func TestCRUDPublicationAndFormSnapshots(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	r := formRequest(url.Values{"name": {"New game"}, "slug": {"new-game"}, "audience": {"member"}, "details_audience": {"access"}, "mode": {"request"}, "type": {"game"}, "focal_x": {"50"}, "focal_y": {"50"}, "position": {"-10"}, "published": {"on"}, "field_0_label": {"Original label"}, "field_0_type": {"short"}, "field_0_required": {"on"}})
	sid, e := a.saveService(admin, 0, r)
	if e != nil {
		t.Fatal(e)
	}
	v := s.service(sid)
	id, e := s.Submit(alice, v, "access", "Please invite me", "", map[string]string{"f0": "Original answer"})
	if e != nil {
		t.Fatal(e)
	}
	r.Form.Set("field_0_label", "Changed label")
	if _, e = a.saveService(admin, sid, r); e != nil {
		t.Fatal(e)
	}
	req := s.request(alice, id)
	if req.Fields[0].Label != "Original label" || req.Fields[0].Value != "Original answer" {
		t.Fatal("submitted snapshot changed")
	}
	if v.Position != -10 {
		t.Fatal("reordering not saved")
	}
	r.Form.Del("published")
	a.saveService(admin, sid, r)
	if s.discover(alice, s.service(sid)) {
		t.Fatal("unpublished discoverable")
	}
	if s.request(alice, id) == nil {
		t.Fatal("history lost on unpublish")
	}
	link := formRequest(url.Values{"label": {"Public bypass"}, "url": {"https://example.invalid"}, "placement": {"global"}, "audience": {"access"}, "style": {"primary"}, "icon": {"link"}, "enabled": {"on"}})
	if a.saveLink(admin, 0, link) == nil {
		t.Fatal("access link without associated service")
	}
	link.Form.Set("access_service", fmt.Sprint(sid))
	if e = a.saveLink(admin, 0, link); e != nil {
		t.Fatal(e)
	}
	if len(s.LinksFor(alice, "global", 0)) != 0 {
		t.Fatal("unpublished parent bypass")
	}
}
func TestLoginLogoutCSRFAndPersistence(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, "alice")
	_, status := get(t, client, server.URL+"/requests")
	if status != 200 {
		t.Fatal("login failed", status)
	}
	resp, e := client.PostForm(server.URL+"/services/plex/requests", url.Values{"kind": {"access"}, "reason": {"please"}})
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("CSRF missing accepted", resp.StatusCode)
	}
	before := a.Store.User(alice.ID).Generation
	r := formRequest(url.Values{"role": {"member"}, "confirm": {"on"}})
	if e = a.saveMember(admin, alice.ID, r); e != nil {
		t.Fatal(e)
	}
	if a.Store.User(alice.ID).Generation <= before {
		t.Fatal("sessions not invalidated")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, status = get(t, client, server.URL+"/requests")
	if status != 303 {
		t.Fatal("disabled session accepted", status)
	}
	ownerClient := loginClient(t, server, "owner")
	post(t, ownerClient, server.URL, "/account/logout", url.Values{})
	ownerClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, status = get(t, ownerClient, server.URL+"/admin")
	if status != 303 {
		t.Fatal("logout failed", status)
	}
	path := filepath.Join(a.Config.DataDir, "test.db")
	n := count(t, a.Store, "SELECT count(*) FROM services")
	a.Store.DB.Close()
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	if count(t, reopened, "SELECT count(*) FROM services") != n {
		t.Fatal("restart lost data")
	}
}
func TestRateLimits(t *testing.T) {
	a, _, _, _ := fixture(t)
	if a.Store.Limited("key", 2, time.Minute) {
		t.Fatal("first blocked")
	}
	if a.Store.Limited("key", 2, time.Minute) {
		t.Fatal("second blocked")
	}
	if !a.Store.Limited("key", 2, time.Minute) {
		t.Fatal("rate limit absent")
	}
}
func TestEveryPageRenders(t *testing.T) {
	a, _, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := loginClient(t, server, "owner")
	for _, path := range []string{"/", "/services/plex", "/services/campfire", "/my-access", "/requests", "/notifications", "/account/password", "/admin", "/admin/services", "/admin/services/new", "/admin/services/1", "/admin/categories", "/admin/categories/new", "/admin/categories/1", "/admin/links", "/admin/links/new", "/admin/links/1", "/admin/members", "/admin/members/2", "/admin/access", "/admin/followups", "/admin/announcements", "/admin/announcements/new", "/admin/settings", "/admin/audit", "/admin/preview/1?as=member"} {
		body, status := get(t, c, server.URL+path)
		if status != 200 {
			t.Errorf("%s: status %d", path, status)
		}
		if !strings.Contains(body, "</html>") {
			t.Errorf("%s: incomplete template", path)
		}
		if strings.Contains(body, "ZgotmplZ") {
			t.Errorf("%s: unsafe template value", path)
		}
	}
}
func formRequest(v url.Values) *http.Request {
	r := httptest.NewRequest("POST", "http://localhost/", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	return r
}

var csrfRE = regexp.MustCompile(`name="gorilla.csrf.Token" value="([^"]+)"`)

func get(t *testing.T, c *http.Client, address string) (string, int) {
	t.Helper()
	r, e := c.Get(address)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	b, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	return string(b), r.StatusCode
}
func loginClient(t *testing.T, s *httptest.Server, name string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	post(t, c, s.URL, "/account/login", url.Values{"username": {name}, "password": {"a long test password"}})
	enrollTestClient(t, c, s.URL)
	return c
}
func post(t *testing.T, c *http.Client, base, path string, values url.Values) (string, int) {
	t.Helper()
	body, _ := get(t, c, base+"/account/login")
	match := csrfRE.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("missing csrf field", body)
	}
	values.Set("gorilla.csrf.Token", match[1])
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

func TestProductionCookiesAndOriginProtection(t *testing.T) {
	a, _, _, _ := fixture(t)
	a.Config.Production = true
	a.Sessions.Cookie.Secure = true
	server := httptest.NewTLSServer(a.Handler())
	defer server.Close()
	c := server.Client()
	c.Jar, _ = cookiejar.New(nil)
	body, status := post(t, c, server.URL, "/account/login", url.Values{"username": {"alice"}, "password": {"a long test password"}})
	enrollTestClient(t, c, server.URL)
	body, status = get(t, c, server.URL+"/")
	if status != 200 || !strings.Contains(body, "Make yourself at home") {
		t.Fatal("HTTPS login failed", status)
	}
	body, _ = get(t, c, server.URL+"/account/password")
	match := csrfRE.FindStringSubmatch(body)
	req, _ := http.NewRequest("POST", server.URL+"/account/logout", strings.NewReader(url.Values{"gorilla.csrf.Token": {match[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.invalid")
	resp, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("cross-origin mutation accepted")
	}
	fresh := server.Client()
	resp, e = fresh.Get(server.URL + "/account/login")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_gorilla_csrf" && (!cookie.Secure || !cookie.HttpOnly) {
			t.Fatal("insecure production CSRF cookie")
		}
	}
	if resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser form origin policy regression")
	}
}

func TestAudienceMatrixAndSnapshotPrivacy(t *testing.T) {
	a, admin, alice, bob := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "campfire")
	s.DB.Exec("UPDATE categories SET audience='public' WHERE id=?", v.CategoryID)
	for _, public := range []bool{false, true} {
		s.DB.Exec("UPDATE settings SET public=?", public)
		for _, aud := range []string{"public", "member", "access", "admin"} {
			s.DB.Exec("UPDATE services SET audience=?,details_audience='access' WHERE id=?", aud, v.ID)
			current := s.service(v.ID)
			for _, subject := range []*User{nil, alice, admin} {
				want := subject == admin || aud == "public" && (subject != nil || public) || aud == "member" && subject != nil
				if got := s.discover(subject, current); got != want {
					t.Errorf("public=%v audience=%s subject=%v want=%v got=%v", public, aud, subject, want, got)
				}
			}
		}
	}
	s.DB.Exec("UPDATE services SET audience='member' WHERE id=?", v.ID)
	s.Write(func(tx *sql.Tx) error { _, e := grant(tx, admin.ID, alice.ID, v.ID, "next steps", ""); return e })
	s.DB.Exec("UPDATE services SET name='HIDDEN NEW NAME',audience='admin' WHERE id=?", v.ID)
	access := s.Accesses(alice)
	if len(access) != 1 || access[0].ServiceName != "Campfire" || access[0].Service != nil {
		t.Fatal("current hidden service metadata leaked into access history")
	}
	if len(s.Accesses(bob)) != 0 {
		t.Fatal("other access records exposed")
	}
}
func TestManualAccessConflicts(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	v := serviceNamed(t, a.Store, "plex")
	base := url.Values{"action": {"grant"}, "user_id": {fmt.Sprint(alice.ID)}, "service_id": {fmt.Sprint(v.ID)}, "confirm": {"on"}, "next_steps": {"Use the external invite"}}
	if e := a.saveAccess(admin, formRequest(base)); e != nil {
		t.Fatal(e)
	}
	if e := a.saveAccess(admin, formRequest(base)); e == nil {
		t.Fatal("blind concurrent upsert accepted")
	}
	records := a.Store.Accesses(admin)
	if len(records) != 1 {
		t.Fatal("missing record")
	}
	rec := records[0]
	base.Set("version", fmt.Sprint(rec.Version))
	base.Set("next_steps", "Updated safe instructions")
	if e := a.saveAccess(admin, formRequest(base)); e != nil {
		t.Fatal(e)
	}
	r := formRequest(url.Values{"action": {"revoke"}, "confirm": {"on"}, "access_id": {fmt.Sprint(rec.ID)}, "version": {fmt.Sprint(rec.Version)}})
	if e := a.saveAccess(admin, r); e == nil {
		t.Fatal("stale revocation accepted")
	}
	r.Form.Set("version", fmt.Sprint(rec.Version+1))
	if e := a.saveAccess(admin, r); e != nil {
		t.Fatal(e)
	}
	if a.Store.hasAccess(alice, v.ID) {
		t.Fatal("revoked record still unlocks")
	}
	if count(t, a.Store, "SELECT count(*) FROM access_history WHERE access_id=?", rec.ID) != 3 {
		t.Fatal("access history incomplete")
	}
}
func TestConfigurationCRUDAndSchedules(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	r := formRequest(url.Values{"name": {"New category"}, "audience": {"member"}, "position": {"-3"}})
	if e := a.saveCategory(admin, 0, r); e != nil {
		t.Fatal(e)
	}
	var id int
	s.DB.QueryRow("SELECT id FROM categories WHERE name='New category'").Scan(&id)
	r.Form.Set("name", "Renamed")
	if e := a.saveCategory(admin, id, r); e != nil {
		t.Fatal(e)
	}
	lr := formRequest(url.Values{"label": {"A resource"}, "url": {"http://internal-host:8080/path"}, "placement": {"category"}, "parent_id": {fmt.Sprint(id)}, "audience": {"member"}, "style": {"secondary"}, "icon": {"link"}, "position": {"-2"}, "enabled": {"on"}})
	if e := a.saveLink(admin, 0, lr); e != nil {
		t.Fatal(e)
	}
	links := s.LinksFor(alice, "category", id)
	if len(links) != 1 || links[0].Position != -2 {
		t.Fatal("link order or visibility wrong")
	}
	lr.Form.Set("url", "https://other-host.invalid")
	if e := a.saveLink(admin, links[0].ID, lr); e != nil {
		t.Fatal(e)
	}
	r.Form.Set("action", "delete")
	r.Form.Set("confirm", "on")
	if e := a.saveCategory(admin, id, r); e == nil {
		t.Fatal("deleted category with dependent links")
	}
	lr.Form.Set("action", "delete")
	lr.Form.Set("confirm", "on")
	if e := a.saveLink(admin, links[0].ID, lr); e != nil {
		t.Fatal(e)
	}
	if e := a.saveCategory(admin, id, r); e != nil {
		t.Fatal(e)
	}
	v := serviceNamed(t, s, "development-network")
	ar := formRequest(url.Values{"title": {"Private notice"}, "body": {"PRIVATE_ANNOUNCEMENT_SENTINEL"}, "placement": {"service"}, "parent_id": {fmt.Sprint(v.ID)}, "audience": {"access"}, "access_service": {fmt.Sprint(v.ID)}, "enabled": {"on"}})
	if e := a.saveAnnouncement(admin, 0, ar); e != nil {
		t.Fatal(e)
	}
	if len(s.announcements(alice, "service", v.ID)) != 0 {
		t.Fatal("private announcement leaked")
	}
	all := s.AllAnnouncements()
	ar.Form.Set("audience", "member")
	ar.Form.Set("starts", stamp(time.Now().Add(time.Hour)))
	if e := a.saveAnnouncement(admin, all[0].ID, ar); e != nil {
		t.Fatal(e)
	}
	if len(s.announcements(alice, "service", v.ID)) != 0 {
		t.Fatal("future announcement visible")
	}
	ar.Form.Set("starts", "")
	ar.Form.Set("ends", stamp(time.Now().Add(-time.Hour)))
	if e := a.saveAnnouncement(admin, all[0].ID, ar); e != nil {
		t.Fatal(e)
	}
	if len(s.announcements(alice, "service", v.ID)) != 0 {
		t.Fatal("expired announcement visible")
	}
}
func TestRecommendationsNeverGrantOrReveal(t *testing.T) {
	a, admin, _, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "development-network")
	token, e := s.IssueToken(admin.ID, "invite", "recommended", "", 0, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Redeem(token, "a long test password"); e != nil {
		t.Fatal(e)
	}
	var id int
	s.DB.QueryRow("SELECT id FROM users WHERE username='recommended'").Scan(&id)
	u := s.User(id)
	view := s.permitted(u, *v)
	if view == nil || !view.Recommended || view.Details || s.hasAccess(u, v.ID) {
		t.Fatal("recommendation visibility or grant boundary wrong")
	}
	s.DB.Exec("UPDATE services SET audience='admin' WHERE id=?", v.ID)
	if s.permitted(u, *s.service(v.ID)) != nil {
		t.Fatal("recommendation disclosed hidden service")
	}
}

func TestArtworkUploadAndMediaAuthorizationHTTP(t *testing.T) {
	a, _, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, "owner")
	page, _ := get(t, client, server.URL+"/admin/services/1")
	csrfToken := csrfRE.FindStringSubmatch(page)[1]
	var pngBytes bytes.Buffer
	png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 80, 60)))
	upload := func(data []byte) int {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		writer.WriteField("gorilla.csrf.Token", csrfToken)
		file, _ := writer.CreateFormFile("artwork_file", "untrusted-name.png")
		file.Write(data)
		writer.Close()
		req, _ := http.NewRequest("POST", server.URL+"/admin/artwork/1", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Origin", server.URL)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := upload(pngBytes.Bytes()); status != 200 {
		t.Fatal("valid upload failed", status)
	}
	v := a.Store.service(1)
	if !strings.HasPrefix(v.Config.Artwork, "/media/") {
		t.Fatal("upload not routed through authorized media")
	}
	if strings.Contains(v.Config.Artwork, "untrusted-name") {
		t.Fatal("original filename used")
	}
	anon := server.Client()
	_, status := get(t, anon, server.URL+v.Config.Artwork)
	if status != 404 {
		t.Fatal("anonymous protected media exposed", status)
	}
	member := loginClient(t, server, "alice")
	resp, e := member.Get(server.URL + v.Config.Artwork)
	if e != nil {
		t.Fatal(e)
	}
	if resp.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatal("not reencoded")
	}
	im, _, e := image.Decode(resp.Body)
	resp.Body.Close()
	if e != nil || im.Bounds().Dx() != 80 {
		t.Fatal("decoded upload incorrect")
	}
	a.Store.DB.Exec("UPDATE services SET published=0 WHERE id=1")
	_, status = get(t, member, server.URL+v.Config.Artwork)
	if status != 404 {
		t.Fatal("unpublished image exposed")
	}
	if status := upload([]byte("<svg onload='alert(1)'/>")); status != 400 {
		t.Fatal("active image accepted", status)
	}
}

func TestFulfillmentRollsBackOnSetupRecordFailure(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	s := a.Store
	v := serviceNamed(t, s, "plex")
	id, e := s.Submit(alice, v, "access", "Library access", "", map[string]string{"f0": "alice@example.invalid"})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Transition(admin, id, 1, "Approved - Setup Pending", "", "", "", false); e != nil {
		t.Fatal(e)
	}
	before := count(t, s, "SELECT count(*) FROM notifications")
	s.DB.Exec("UPDATE services SET published=0 WHERE id=?", v.ID)
	if e = s.Transition(admin, id, 2, "Fulfilled", "Setup note", "Next steps", "", true); e == nil {
		t.Fatal("fulfillment on unpublished service succeeded")
	}
	record := s.request(alice, id)
	if record.State != "Approved - Setup Pending" || record.Version != 2 {
		t.Fatal("request update did not roll back")
	}
	if count(t, s, "SELECT count(*) FROM access_records") != 0 || count(t, s, "SELECT count(*) FROM notifications") != before {
		t.Fatal("failed fulfillment left partial writes")
	}
	if len(s.Messages(id, false)) != 0 {
		t.Fatal("failed fulfillment left a member message")
	}
}

func enrollTestClient(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	body, status := post(t, c, base, "/account/security", url.Values{"action": {"totp-start"}})
	match := regexp.MustCompile(`id="totp-secret">([^<]+)`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("enrollment setup failed: %d %s", status, body)
	}
	code, e := totp.GenerateCode(match[1], time.Now())
	if e != nil {
		t.Fatal(e)
	}
	body, status = post(t, c, base, "/account/security", url.Values{"action": {"totp-confirm"}, "code": {code}})
	if status != 200 || !strings.Contains(body, "Save your recovery codes") {
		t.Fatalf("enrollment failed: %d %s", status, body)
	}
	return match[1]
}

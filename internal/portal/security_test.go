package portal

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func pendingClient(t *testing.T, server *httptest.Server, name string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	post(t, c, server.URL, "/account/login", url.Values{"username": {name}, "password": {"a long test password"}})
	return c
}
func jsonPost(t *testing.T, c *http.Client, base, path string, data any) (map[string]any, int) {
	t.Helper()
	body, _ := get(t, c, base+"/account/login")
	token := csrfRE.FindStringSubmatch(body)[1]
	b, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("X-CSRF-Token", token)
	res, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var v map[string]any
	json.NewDecoder(res.Body).Decode(&v)
	return v, res.StatusCode
}
func TestMFAPendingCannotAccessPortal(t *testing.T) {
	a, _, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := pendingClient(t, server, "owner")
	for _, path := range []string{"/", "/admin", "/requests", "/my-access", "/my-devices", "/services/development-network", "/account/totp-qr"} {
		body, _ := get(t, c, server.URL+path)
		assertNo(t, body, "Wait for the administrator’s separate enrollment instructions.", "My laptop", "YOUR COMMUNITY, THOUGHTFULLY MANAGED")
	}
	body, status := post(t, c, server.URL, "/account/security", url.Values{"action": {"codes"}, "confirm": {"on"}})
	if status != 200 || !strings.Contains(body, "Enroll a login method first") {
		t.Fatal("enrollment session changed security")
	}
	enrollTestClient(t, c, server.URL)
	body, _ = get(t, c, server.URL+"/")
	if !strings.Contains(body, "Make yourself at home") {
		t.Fatal("enrollment did not establish full login")
	}
}
func TestTOTPReplayAndDisabledSessions(t *testing.T) {
	a, _, alice, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := pendingClient(t, server, "alice")
	key := enrollTestClient(t, c, server.URL)
	u := a.Store.User(alice.ID)
	code, _ := totp.GenerateCode(key, time.Now())
	if a.checkTOTP(u, code) == nil {
		t.Fatal("enrollment code replay accepted")
	}
	if a.checkTOTP(u, "00000") == nil {
		t.Fatal("malformed code accepted")
	}
	code, _ = totp.GenerateCode(key, time.Now().Add(30*time.Second))
	if e := a.checkTOTP(u, code); e != nil {
		t.Fatal(e)
	}
	if a.checkTOTP(u, code) == nil {
		t.Fatal("TOTP replay accepted")
	}
	a.Store.DB.Exec("UPDATE users SET enabled=0 WHERE id=?", u.ID)
	body, _ := get(t, c, server.URL+"/")
	if !strings.Contains(body, "Welcome back.") {
		t.Fatal("disabled session persisted")
	}
}
func TestRecoveryCodesAtomicAndFactorReset(t *testing.T) {
	a, _, alice, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := loginClient(t, server, "alice")
	body, _ := post(t, c, server.URL, "/account/security", url.Values{"action": {"codes"}, "confirm": {"on"}})
	codes := regexp.MustCompile(`<code>([a-f0-9]{24})</code>`).FindAllStringSubmatch(body, -1)
	if len(codes) != 10 {
		t.Fatal("missing recovery codes")
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Jar: jar}
			b, _ := post(t, client, server.URL, "/account/recovery", url.Values{"username": {"alice"}, "code": {codes[0][1]}})
			results <- strings.Contains(b, "Before entering Waypoint")
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for success := range results {
		if success {
			n++
		}
	}
	if n != 1 {
		t.Fatal("recovery code concurrency", n)
	}
	if count(t, a.Store, "SELECT count(*) FROM recovery_codes WHERE user_id=?", alice.ID) != 0 {
		t.Fatal("codes not invalidated after reset")
	}
	b, _ := get(t, c, server.URL+"/")
	if !strings.Contains(b, "Welcome back.") {
		t.Fatal("old session survived recovery")
	}
}
func TestPasskeyCeremonyBoundaries(t *testing.T) {
	a, _, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := pendingClient(t, server, "alice")
	other := pendingClient(t, server, "bob")
	v, status := jsonPost(t, c, server.URL, "/account/passkeys/register-begin", map[string]string{"name": "Laptop"})
	if status != 200 {
		t.Fatal(v)
	}
	pk := v["publicKey"].(map[string]any)
	sel := pk["authenticatorSelection"].(map[string]any)
	if sel["userVerification"] != "required" || sel["residentKey"] != "required" {
		t.Fatal("weak passkey registration options")
	}
	_, status = jsonPost(t, other, server.URL, "/account/passkeys/register-finish", map[string]string{})
	if status != 400 {
		t.Fatal("cross-session ceremony accepted")
	}
	_, status = jsonPost(t, c, server.URL, "/account/passkeys/register-finish", map[string]string{})
	if status != 400 {
		t.Fatal("invalid attestation accepted")
	}
	if count(t, a.Store, "SELECT count(*) FROM auth_challenges WHERE purpose='register'") != 0 {
		t.Fatal("failed ceremony was reusable")
	}
	v, status = jsonPost(t, c, server.URL, "/account/passkeys/login-begin", map[string]string{})
	if status != 200 {
		t.Fatal(v)
	}
	if v["publicKey"].(map[string]any)["userVerification"] != "required" {
		t.Fatal("login must verify user")
	}
	a.Store.DB.Exec("UPDATE auth_challenges SET expires='2000-01-01T00:00:00Z'")
	_, status = jsonPost(t, c, server.URL, "/account/passkeys/login-finish", map[string]string{})
	if status != 400 {
		t.Fatal("expired challenge accepted")
	}
}
func TestPasswordResetKeepsFactorsAndLocalRecovery(t *testing.T) {
	a, admin, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	loginClient(t, server, "owner")
	token, e := a.Store.IssueToken(admin.ID, "reset", "", "", admin.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Store.Redeem(token, "a new long password"); e != nil {
		t.Fatal(e)
	}
	enabled, _ := a.factors(admin.ID)
	if !enabled {
		t.Fatal("password reset removed factor")
	}
	if e = a.Store.RecoverFactors("owner", "another long password"); e != nil {
		t.Fatal(e)
	}
	enabled, _ = a.factors(admin.ID)
	if enabled {
		t.Fatal("local factor recovery failed")
	}
}
func TestSecuritySecretsEncryptedAndLastFactorProtected(t *testing.T) {
	a, _, alice, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := pendingClient(t, server, "alice")
	key := enrollTestClient(t, c, server.URL)
	var raw []byte
	a.Store.DB.QueryRow("SELECT totp FROM account_security WHERE user_id=?", alice.ID).Scan(&raw)
	if bytes.Contains(raw, []byte(key)) {
		t.Fatal("plaintext TOTP persisted")
	}
	body, _ := post(t, c, server.URL, "/account/security", url.Values{"action": {"totp-remove"}, "confirm": {"on"}})
	if !strings.Contains(body, "Add a passkey before removing") {
		t.Fatal("last login method removed")
	}
	// Missing encryption key must not be silently replaced after restart.
	a.Config.SecretsDir = t.TempDir()
	if e := a.initSecurity(); e == nil {
		t.Fatal("missing key accepted with encrypted data")
	}
}
func TestAdminFactorResetLocksPasswordEnrollment(t *testing.T) {
	a, _, alice, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := loginClient(t, server, "owner")
	member := loginClient(t, server, "alice")
	body, status := post(t, c, server.URL, "/admin/factor-reset", url.Values{"user_id": {"2"}, "confirm": {"on"}})
	if status != 200 || !strings.Contains(body, "Single-use link") {
		t.Fatal("factor reset failed")
	}
	var locked bool
	a.Store.DB.QueryRow("SELECT enrollment_locked FROM users WHERE id=?", alice.ID).Scan(&locked)
	if !locked {
		t.Fatal("reset did not require setup link")
	}
	b, _ := post(t, member, server.URL, "/account/login", url.Values{"username": {"alice"}, "password": {"a long test password"}})
	if strings.Contains(b, "Before entering Waypoint") {
		t.Fatal("old password bypassed recovery link")
	}
	token := regexp.MustCompile(`token=([a-f0-9]+)`).FindStringSubmatch(body)[1]
	if e := a.Store.Redeem(token, "a replacement long password"); e != nil {
		t.Fatal(e)
	}
	a.Store.DB.QueryRow("SELECT enrollment_locked FROM users WHERE id=?", alice.ID).Scan(&locked)
	if locked {
		t.Fatal("setup link did not unlock enrollment")
	}
}
func TestNotificationMailOutboxTransactional(t *testing.T) {
	a, _, alice, _ := fixture(t)
	s := a.Store
	s.DB.Exec("UPDATE users SET email='alice@example.invalid',email_verified=1 WHERE id=?", alice.ID)
	s.DB.Exec("UPDATE mail_settings SET enabled=1")
	e := s.Write(func(tx *sql.Tx) error {
		if e := notify(tx, alice.ID, 0, 0, "private update"); e != nil {
			return e
		}
		return ErrConflict
	})
	if e == nil {
		t.Fatal("rollback expected")
	}
	if count(t, s, "SELECT count(*) FROM mail_outbox") != 0 {
		t.Fatal("outbox survived rollback")
	}
	if e = s.Write(func(tx *sql.Tx) error { return notify(tx, alice.ID, 0, 0, "private update") }); e != nil {
		t.Fatal(e)
	}
	if count(t, s, "SELECT count(*) FROM mail_outbox") != 1 {
		t.Fatal("notification not queued")
	}
	s.DB.Exec("UPDATE users SET email_notifications=0 WHERE id=?", alice.ID)
	s.Write(func(tx *sql.Tx) error { return notify(tx, alice.ID, 0, 0, "second update") })
	if count(t, s, "SELECT count(*) FROM mail_outbox") != 1 {
		t.Fatal("preference ignored")
	}
}

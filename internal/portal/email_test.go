package portal

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"waypoint/web"
)

// A local SMTP peer exercises real STARTTLS/implicit TLS and AUTH without any
// external connections. Trust is injected only by this test, never via settings.
func smtpFixture(t *testing.T, implicit bool) (string, int, *tls.Config, <-chan string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	cert := ts.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	box := make(chan string, 4)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				secured := implicit
				if implicit {
					c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				}
				reader := bufio.NewReader(c)
				c.Write([]byte("220 test SMTP\r\n"))
				authed := false
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					line = strings.TrimSpace(line)
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if secured {
							c.Write([]byte("250-test\r\n250 AUTH PLAIN\r\n"))
						} else {
							c.Write([]byte("250-test\r\n250 STARTTLS\r\n"))
						}
					case line == "STARTTLS":
						c.Write([]byte("220 Begin TLS\r\n"))
						c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
						reader = bufio.NewReader(c)
						secured = true
					case strings.HasPrefix(line, "AUTH PLAIN"):
						value := strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN"))
						if value == "" {
							c.Write([]byte("334 \r\n"))
							value, _ = reader.ReadString('\n')
							value = strings.TrimSpace(value)
						}
						b, _ := base64.StdEncoding.DecodeString(value)
						authed = secured && string(b) == "\x00test-user\x00test-password"
						if authed {
							c.Write([]byte("235 Authenticated\r\n"))
						} else {
							c.Write([]byte("535 Denied\r\n"))
						}
					case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
						if !authed {
							c.Write([]byte("530 Authentication required\r\n"))
						} else {
							c.Write([]byte("250 OK\r\n"))
						}
					case line == "DATA":
						c.Write([]byte("354 Send data\r\n"))
						var body strings.Builder
						for {
							line, e = reader.ReadString('\n')
							if e != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						box <- body.String()
						c.Write([]byte("250 Accepted\r\n"))
					case line == "QUIT":
						c.Write([]byte("221 Goodbye\r\n"))
						return
					default:
						c.Write([]byte("250 OK\r\n"))
					}
				}
			}(conn)
		}
	}()
	return "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}, box
}
func TestSMTPTLSAndAuthentication(t *testing.T) {
	a, _, _, _ := fixture(t)
	for _, implicit := range []bool{false, true} {
		host, port, trust, box := smtpFixture(t, implicit)
		mode := "starttls"
		if implicit {
			mode = "tls"
		}
		c := MailSettings{Host: host, Port: port, Mode: mode, Username: "test-user", Password: a.seal("smtp", []byte("test-password")), Sender: "portal@example.invalid", Name: "Waypoint"}
		if e := a.sendMailTLS(context.Background(), c, "friend@example.invalid", mailBody{"Test delivery", "Generic update. No credentials."}, 1, trust); e != nil {
			t.Fatal(e)
		}
		select {
		case body := <-box:
			if !strings.Contains(body, "Generic update") {
				t.Fatal("missing body")
			}
			assertNo(t, body, "test-password")
		case <-time.After(3 * time.Second):
			t.Fatal("SMTP message not received")
		}
		if e := a.sendMail(context.Background(), c, "friend@example.invalid", mailBody{"Test", "Body"}, 2); e == nil {
			t.Fatal("untrusted TLS certificate accepted")
		}
		c.Password = a.seal("smtp", []byte("wrong-password"))
		if e := a.sendMailTLS(context.Background(), c, "friend@example.invalid", mailBody{"Test", "Body"}, 3, trust); e == nil {
			t.Fatal("incorrect SMTP password accepted")
		}
	}
}
func TestEmailVerificationOwnershipAndNotifications(t *testing.T) {
	a, _, alice, _ := fixture(t)
	a.Store.DB.Exec("UPDATE mail_settings SET enabled=1")
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	c := loginClient(t, server, "alice")
	other := loginClient(t, server, "bob")
	body, _ := post(t, c, server.URL, "/account/security", url.Values{"action": {"email"}, "email": {"alice@example.invalid"}, "notify": {"on"}})
	if strings.Contains(body, "error\" role") {
		t.Fatal("email setup failed")
	}
	var payload []byte
	a.Store.DB.QueryRow("SELECT payload FROM mail_outbox WHERE kind='verify'").Scan(&payload)
	raw, e := a.unseal("email:verify", payload)
	if e != nil {
		t.Fatal(e)
	}
	start := strings.Index(string(raw), "token=")
	token := string(raw)[start+6 : start+70]
	body, _ = post(t, other, server.URL, "/account/verify-email", url.Values{"token": {token}})
	if !strings.Contains(body, "invalid or expired") {
		t.Fatal("cross-account email verification accepted")
	}
	body, _ = post(t, c, server.URL, "/account/verify-email", url.Values{"token": {token}})
	if !strings.Contains(body, "Your email is verified") {
		t.Fatal("email did not verify")
	}
	if count(t, a.Store, "SELECT email_verified FROM users WHERE id=?", alice.ID) != 1 {
		t.Fatal("verification missing")
	}
	body, _ = post(t, c, server.URL, "/account/verify-email", url.Values{"token": {token}})
	if !strings.Contains(body, "invalid or expired") {
		t.Fatal("verification token replay accepted")
	}
}
func TestMailQueueRetryCancellationAndRestart(t *testing.T) {
	a, _, alice, _ := fixture(t)
	a.Store.DB.Exec("UPDATE mail_settings SET enabled=1,host='127.0.0.1',port=1,sender='portal@example.invalid'")
	a.Store.DB.Exec("UPDATE users SET email='alice@example.invalid',email_verified=1 WHERE id=?", alice.ID)
	a.Store.Write(func(tx *sql.Tx) error {
		return a.queueMail(tx, alice.ID, "test", "alice@example.invalid", "", mailBody{"Test", "Non-secret body"})
	})
	a.deliverOne(context.Background())
	if count(t, a.Store, "SELECT attempts FROM mail_outbox WHERE id=1") != 1 {
		t.Fatal("retry not recorded")
	}
	a.Store.DB.Exec("UPDATE mail_outbox SET state='sending',available='2000-01-01T00:00:00Z'")
	restarted, e := New(a.Store, a.Config, web.Assets)
	if e != nil {
		t.Fatal(e)
	}
	restarted.deliverOne(context.Background())
	if count(t, a.Store, "SELECT attempts FROM mail_outbox WHERE id=1") != 2 {
		t.Fatal("lease not recovered")
	}
	a.Store.DB.Exec("UPDATE mail_outbox SET available='2000-01-01T00:00:00Z'")
	a.Store.DB.Exec("UPDATE users SET enabled=0 WHERE id=?", alice.ID)
	restarted.deliverOne(context.Background())
	if count(t, a.Store, "SELECT count(*) FROM mail_outbox WHERE state='cancelled' AND payload IS NULL") != 1 {
		t.Fatal("disabled recipient was not cancelled")
	}
}
func TestInvitationEmailAtomicAndSecretsPrivate(t *testing.T) {
	a, admin, _, _ := fixture(t)
	deliver := func(tx *sql.Tx, token, email string, id int) error {
		return a.queueMail(tx, id, "invite", email, hashToken(token), mailBody{"Invitation", a.Config.BaseURL + "/account/redeem?token=" + token})
	}
	if _, e := a.Store.issueToken(admin.ID, "invite", "charlie", "charlie@example.invalid", 0, deliver); e == nil {
		t.Fatal("SMTP disabled accepted email invite")
	}
	if count(t, a.Store, "SELECT count(*) FROM tokens WHERE username='charlie'") != 0 {
		t.Fatal("token survived failed queue transaction")
	}
	a.Store.DB.Exec("UPDATE mail_settings SET enabled=1")
	token, e := a.Store.issueToken(admin.ID, "invite", "charlie", "charlie@example.invalid", 0, deliver)
	if e != nil {
		t.Fatal(e)
	}
	var payload []byte
	a.Store.DB.QueryRow("SELECT payload FROM mail_outbox WHERE kind='invite'").Scan(&payload)
	assertNo(t, string(payload), token)
	if e = a.Store.Redeem(token, "a long test password"); e != nil {
		t.Fatal(e)
	}
	a.deliverOne(context.Background())
	if count(t, a.Store, "SELECT count(*) FROM mail_outbox WHERE state='cancelled' AND payload IS NULL") != 1 {
		t.Fatal("consumed invite was sent")
	}
	data, e := os.ReadFile(filepath.Join(a.Config.DataDir, "secrets", "account.key"))
	if e != nil || len(data) != 32 {
		t.Fatal("persistent key missing")
	}
}

func TestEmailWorkerGenericPrivacySuccessAndEligibility(t *testing.T) {
	a, _, alice, _ := fixture(t)
	a.Store.DB.Exec("UPDATE mail_settings SET enabled=1")
	a.Store.DB.Exec("UPDATE users SET email='alice@example.invalid',email_verified=1 WHERE id=?", alice.ID)
	a.Store.Write(func(tx *sql.Tx) error { return notify(tx, alice.ID, 0, 0, "PRIVATE_NOTIFICATION_SENTINEL") })
	calls := 0
	sender := func(ctx context.Context, c MailSettings, to string, b mailBody, id int) error {
		calls++
		if to != "alice@example.invalid" {
			t.Fatal("wrong recipient")
		}
		assertNo(t, b.Body+b.Subject, "PRIVATE_NOTIFICATION_SENTINEL")
		if !strings.Contains(b.Body, "/notifications") {
			t.Fatal("missing inbox link")
		}
		return nil
	}
	a.deliverOneUsing(context.Background(), sender)
	if calls != 1 || count(t, a.Store, "SELECT count(*) FROM mail_outbox WHERE state='sent' AND payload IS NULL") != 1 {
		t.Fatal("success not recorded")
	}
	a.deliverOneUsing(context.Background(), sender)
	if calls != 1 {
		t.Fatal("sent event redelivered")
	}
	a.Store.Write(func(tx *sql.Tx) error { return notify(tx, alice.ID, 0, 0, "another") })
	a.Store.DB.Exec("UPDATE users SET email_notifications=0 WHERE id=?", alice.ID)
	a.deliverOneUsing(context.Background(), sender)
	if calls != 1 {
		t.Fatal("opted out recipient received mail")
	}
}
func TestSMTPAdminAuthorizationAndSecretRedaction(t *testing.T) {
	a, _, _, _ := fixture(t)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	member := loginClient(t, server, "alice")
	admin := loginClient(t, server, "owner")
	_, status := get(t, member, server.URL+"/admin/email")
	if status != 403 {
		t.Fatal("member read SMTP settings")
	}
	form := url.Values{"action": {"save"}, "enabled": {"on"}, "host": {"smtp.example.invalid"}, "port": {"587"}, "mode": {"starttls"}, "sender": {"portal@example.invalid"}, "username": {"mailer"}, "name": {"Waypoint"}, "password": {"SMTP_SECRET_SENTINEL"}}
	body, status := post(t, admin, server.URL, "/admin/email", form)
	if status != 200 {
		t.Fatal("SMTP save failed")
	}
	assertNo(t, body, "SMTP_SECRET_SENTINEL")
	var encrypted []byte
	a.Store.DB.QueryRow("SELECT password FROM mail_settings").Scan(&encrypted)
	assertNo(t, string(encrypted), "SMTP_SECRET_SENTINEL")
	form.Set("sender", "valid@example.invalid\r\nBcc: attacker@example.invalid")
	body, _ = post(t, admin, server.URL, "/admin/email", form)
	if !strings.Contains(body, "valid sender") {
		t.Fatal("header injection accepted")
	}
	form.Set("mode", "none")
	body, _ = post(t, admin, server.URL, "/admin/email", form)
	if !strings.Contains(body, "Check SMTP") {
		t.Fatal("plaintext SMTP accepted")
	}
}

func TestSecurityMailAtomicAndCannotOptOut(t *testing.T) {
	a, _, alice, _ := fixture(t)
	a.Store.DB.Exec("UPDATE mail_settings SET enabled=1")
	a.Store.DB.Exec("UPDATE users SET email='alice@example.invalid',email_verified=1,email_notifications=0 WHERE id=?", alice.ID)
	e := a.Store.Write(func(tx *sql.Tx) error {
		if e := securityMutation(tx, alice, "test rollback"); e != nil {
			return e
		}
		return ErrConflict
	})
	if e == nil {
		t.Fatal("expected rollback")
	}
	if count(t, a.Store, "SELECT count(*) FROM mail_outbox") != 0 {
		t.Fatal("security email survived rollback")
	}
	e = a.Store.Write(func(tx *sql.Tx) error { return securityMutation(tx, alice, "test security update") })
	if e != nil {
		t.Fatal(e)
	}
	if count(t, a.Store, "SELECT count(*) FROM mail_outbox WHERE kind='security'") != 1 {
		t.Fatal("security notification preference bypassed")
	}
	sent := false
	a.deliverOneUsing(context.Background(), func(_ context.Context, _ MailSettings, _ string, b mailBody, _ int) error {
		sent = true
		if !strings.Contains(b.Body, "/account/security") {
			t.Fatal("missing security link")
		}
		return nil
	})
	if !sent {
		t.Fatal("security message not sent")
	}
}

package portal

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	stdmail "net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"
)

type MailSettings struct {
	Enabled                      bool
	Host                         string
	Port                         int
	Mode, Username, Sender, Name string
	Password                     []byte
}
type MailPage struct {
	Config      MailSettings
	HasPassword bool
	Rows        [][]string
}
type mailBody struct{ Subject, Body string }

func validEmail(s string) bool {
	v, e := stdmail.ParseAddress(s)
	return e == nil && v.Address == s && len(s) <= 254 && !strings.ContainsAny(s, "\r\n")
}
func (a *App) mailConfig() (MailSettings, error) {
	var c MailSettings
	e := a.Store.DB.QueryRow("SELECT enabled,host,port,mode,username,password,sender,name FROM mail_settings WHERE id=1").Scan(&c.Enabled, &c.Host, &c.Port, &c.Mode, &c.Username, &c.Password, &c.Sender, &c.Name)
	return c, e
}
func (a *App) queueMail(tx *sql.Tx, uid int, kind, to, token string, body mailBody) error {
	var enabled bool
	if e := tx.QueryRow("SELECT enabled FROM mail_settings WHERE id=1").Scan(&enabled); e != nil {
		return e
	}
	if !enabled {
		return errors.New("Configure and enable SMTP first")
	}
	if !validEmail(to) {
		return errors.New("A valid email address is required")
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO mail_outbox(user_id,kind,recipient,payload,token_hash,available,created) VALUES(?,?,?,?,?,?,?)", nullable(uid), kind, to, a.seal("email:"+kind, raw), token, now(), now())
	return e
}
func (a *App) updateEmail(r *http.Request, u *User) error {
	email := strings.TrimSpace(r.FormValue("email"))
	if !validEmail(email) {
		return errors.New("Enter a valid email address")
	}
	token := secret()
	return a.Store.Write(func(tx *sql.Tx) error {
		if e := securityIdentity(tx, u); e != nil {
			return e
		}
		var old string
		var verified bool
		if e := tx.QueryRow("SELECT email,email_verified FROM users WHERE id=?", u.ID).Scan(&old, &verified); e != nil {
			return e
		}
		if old == email && verified {
			_, e := tx.Exec("UPDATE users SET email_notifications=? WHERE id=?", r.FormValue("notify") == "on", u.ID)
			return e
		}
		if _, e := tx.Exec("DELETE FROM email_tokens WHERE user_id=?", u.ID); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO email_tokens(hash,user_id,email,kind,expires) VALUES(?,?,?,'verify',?)", hashToken(token), u.ID, email, stamp(time.Now().Add(time.Hour))); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE users SET email_notifications=? WHERE id=?", r.FormValue("notify") == "on", u.ID); e != nil {
			return e
		}
		return a.queueMail(tx, u.ID, "verify", email, hashToken(token), mailBody{"Verify your email address", "Confirm this address for your Waypoint account. This link expires in one hour.\n\n" + a.Config.BaseURL + "/account/verify-email?token=" + token})
	})
}
func (a *App) verifyEmail(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	p := a.page(r, "Verify email", "verify-email")
	p.TokenURL = r.URL.Query().Get("token")
	if r.Method == "POST" {
		if a.Store.Limited(fmt.Sprint("email-verify:", u.ID), 20, 15*time.Minute) {
			a.fail(w, r, 429, "Too many attempts")
			return
		}
		e := a.Store.Write(func(tx *sql.Tx) error {
			if e := securityIdentity(tx, u); e != nil {
				return e
			}
			var email string
			hash := hashToken(r.FormValue("token"))
			if e := tx.QueryRow("SELECT email FROM email_tokens WHERE hash=? AND user_id=? AND kind='verify' AND expires>?", hash, u.ID, now()).Scan(&email); e != nil {
				return errors.New("This verification link is invalid or expired")
			}
			if _, e := tx.Exec("UPDATE users SET email=?,email_verified=1 WHERE id=?", email, u.ID); e != nil {
				return e
			}
			if _, e := tx.Exec("DELETE FROM email_tokens WHERE user_id=?", u.ID); e != nil {
				return e
			}
			return audit(tx, u.ID, "verify email", idTarget("user", u.ID))
		})
		if e != nil {
			p.Error = e.Error()
		} else {
			http.Redirect(w, r, "/account/security?success=Email+verified", 303)
			return
		}
	}
	a.render(w, r, p)
}
func (a *App) emailAdmin(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	if u.Role != "admin" {
		a.fail(w, r, 403, "Administrators only")
		return
	}
	p := a.page(r, "Email delivery", "email-admin")
	var err error
	if r.Method == "POST" {
		if !a.recent(r) {
			http.Redirect(w, r, "/account/security?success=Confirm+your+identity+before+changing+email+settings", 303)
			return
		}
		if a.Store.Limited(fmt.Sprint("email-admin:", u.ID), 20, 15*time.Minute) {
			a.fail(w, r, 429, "Too many email operations")
			return
		}
		switch r.FormValue("action") {
		case "save":
			c, e := a.mailConfig()
			err = e
			if err != nil {
				break
			}
			c.Enabled = r.FormValue("enabled") == "on"
			c.Host = strings.TrimSpace(r.FormValue("host"))
			c.Port = number(r.FormValue("port"))
			c.Mode = r.FormValue("mode")
			c.Username = r.FormValue("username")
			c.Sender = strings.TrimSpace(r.FormValue("sender"))
			c.Name = strings.TrimSpace(r.FormValue("name"))
			if strings.ContainsAny(c.Host, "/:\\ \r\n\t") && net.ParseIP(c.Host) == nil || len(c.Host) > 253 || c.Port < 1 || c.Port > 65535 || !includes([]string{"starttls", "tls"}, c.Mode) || strings.ContainsAny(c.Name+c.Username, "\r\n") || len(c.Name) > 120 || len(c.Username) > 256 {
				err = errors.New("Check SMTP host, port, TLS mode, and sender fields")
				break
			}
			if c.Enabled && (c.Host == "" || !validEmail(c.Sender)) {
				err = errors.New("SMTP host and a valid sender address are required")
				break
			}
			if r.FormValue("clear_password") == "on" {
				c.Password = nil
			}
			if v := r.FormValue("password"); v != "" {
				if len(v) > 4096 {
					err = errors.New("SMTP password too long")
					break
				}
				c.Password = a.seal("smtp", []byte(v))
			}
			err = a.Store.Write(func(tx *sql.Tx) error {
				if e := securityIdentity(tx, u); e != nil {
					return e
				}
				if _, e := tx.Exec("UPDATE mail_settings SET enabled=?,host=?,port=?,mode=?,username=?,password=?,sender=?,name=? WHERE id=1", c.Enabled, c.Host, c.Port, c.Mode, c.Username, c.Password, c.Sender, c.Name); e != nil {
					return e
				}
				return audit(tx, u.ID, "update SMTP settings", "email")
			})
		case "test":
			err = a.Store.Write(func(tx *sql.Tx) error {
				return a.queueMail(tx, u.ID, "test", strings.TrimSpace(r.FormValue("recipient")), "", mailBody{"Waypoint test email", "Your Waypoint SMTP test reached the mail server.\n\n" + a.Config.BaseURL})
			})
		case "retry":
			err = a.Store.Write(func(tx *sql.Tx) error {
				_, e := tx.Exec("UPDATE mail_outbox SET state='queued',attempts=0,available=?,status='Queued for retry' WHERE id=? AND state='failed'", now(), number(r.FormValue("id")))
				return e
			})
		default:
			err = errors.New("Unknown email action")
		}
		if err != nil {
			p.Error = err.Error()
		} else {
			p.Success = "Email settings or delivery queue updated."
		}
	}
	c, e := a.mailConfig()
	if e != nil {
		a.fail(w, r, 500, "Email settings unavailable")
		return
	}
	mp := &MailPage{HasPassword: len(c.Password) > 0}
	c.Password = nil
	mp.Config = c
	p.Mail = mp
	rows, e := a.Store.DB.Query("SELECT id,kind,recipient,state,attempts,status,created FROM mail_outbox ORDER BY id DESC LIMIT 100")
	if e == nil {
		for rows.Next() {
			row := make([]string, 7)
			rows.Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6])
			mp.Rows = append(mp.Rows, row)
		}
		rows.Close()
	}
	a.render(w, r, p)
}
func (a *App) factorReset(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	if u.Role != "admin" || !a.recent(r) {
		a.fail(w, r, 403, "An administrator must confirm their identity in Account security first")
		return
	}
	id := number(r.FormValue("user_id"))
	if id == u.ID || r.FormValue("confirm") != "on" {
		a.fail(w, r, 400, "Confirm identity verification for another member. Use local recovery for your own lost factors.")
		return
	}
	if a.Store.Limited(fmt.Sprint("factor-reset:", u.ID), 10, time.Hour) {
		a.fail(w, r, 429, "Too many recovery operations")
		return
	}
	token := secret()
	e := a.Store.Write(func(tx *sql.Tx) error {
		if e := securityIdentity(tx, u); e != nil {
			return e
		}
		var username, email string
		if e := tx.QueryRow("SELECT username,email FROM users WHERE id=? AND enabled=1", id).Scan(&username, &email); e != nil {
			return errors.New("Enabled member required")
		}
		if e := clearFactors(tx, id); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE users SET enrollment_locked=1 WHERE id=?", id); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO tokens(hash,kind,username,email,user_id,expires) VALUES(?,'factor',?,?,?,?)", hashToken(token), username, email, id, stamp(time.Now().Add(time.Hour))); e != nil {
			return e
		}
		return audit(tx, u.ID, "administrator reset of login factors", idTarget("user", id))
	})
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	p := a.page(r, "Recovery setup link", "token")
	p.TokenURL = a.Config.BaseURL + "/account/redeem?token=" + token
	a.render(w, r, p)
}
func (a *App) StartMail(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.deliverOne(ctx)
			}
		}
	}()
}
func (a *App) deliverOne(ctx context.Context) { a.deliverOneUsing(ctx, a.sendMail) }
func (a *App) deliverOneUsing(ctx context.Context, send func(context.Context, MailSettings, string, mailBody, int) error) {
	c, e := a.mailConfig()
	if e != nil || !c.Enabled {
		return
	}
	var id, uid, nid, attempts int
	var kind, recipient, hash string
	var payload []byte
	lease := secret()
	e = a.Store.Write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("UPDATE mail_outbox SET state='queued',lease=NULL WHERE state='sending' AND available<?", now()); e != nil {
			return e
		}
		if e := tx.QueryRow("SELECT id,coalesce(user_id,0),coalesce(notification_id,0),kind,recipient,payload,coalesce(token_hash,''),attempts FROM mail_outbox WHERE state='queued' AND available<=? ORDER BY id LIMIT 1", now()).Scan(&id, &uid, &nid, &kind, &recipient, &payload, &hash, &attempts); e != nil {
			return e
		}
		_, e := tx.Exec("UPDATE mail_outbox SET state='sending',lease=?,available=? WHERE id=?", lease, stamp(time.Now().Add(2*time.Minute)), id)
		return e
	})
	if e != nil {
		return
	}
	finish := func(state, status string, clearPayload bool) {
		var b any = payload
		if clearPayload {
			b = nil
		}
		_, _ = a.Store.DB.Exec("UPDATE mail_outbox SET state=?,status=?,payload=?,attempts=attempts+1,available=?,lease=NULL WHERE id=? AND lease=?", state, status, b, stamp(time.Now().Add(time.Duration(1<<min(attempts, 8))*time.Minute)), id, lease)
	}
	var body mailBody
	if uid != 0 {
		var enabled bool
		if a.Store.DB.QueryRow("SELECT enabled FROM users WHERE id=?", uid).Scan(&enabled) != nil || !enabled {
			finish("cancelled", "Account unavailable", true)
			return
		}
	}
	if kind == "notification" || kind == "security" {
		var valid bool
		query := "SELECT email_verified=1 AND email=? FROM users WHERE id=?"
		if kind == "notification" {
			query += " AND email_notifications=1"
		}
		a.Store.DB.QueryRow(query, recipient, uid).Scan(&valid)
		if !valid {
			finish("cancelled", "Recipient no longer eligible", true)
			return
		}
	}
	if kind == "notification" {
		found := false
		for _, n := range a.visibleNotifications(a.Store.User(uid), false) {
			if n.ID == nid {
				found = true
				break
			}
		}
		if !found {
			finish("cancelled", "Update no longer visible", true)
			return
		}
		body = mailBody{"Waypoint update", "You have an update in Waypoint. Sign in to view it.\n\n" + a.Config.BaseURL + "/notifications"}
	} else if kind == "security" {
		body = mailBody{"Account security changed", "Your account security settings changed. If you did not make this change, contact your administrator.\n\n" + a.Config.BaseURL + "/account/security"}
	} else {
		b, err := a.unseal("email:"+kind, payload)
		if err != nil {
			finish("failed", "Cannot decrypt queued message", false)
			return
		}
		err = json.Unmarshal(b, &body)
		clear(b)
		if err != nil {
			finish("failed", "Invalid queued message", true)
			return
		}
	}
	if hash != "" {
		var n int
		query := "SELECT count(*) FROM tokens WHERE hash=? AND consumed IS NULL AND expires>?"
		if kind == "verify" {
			query = "SELECT count(*) FROM email_tokens WHERE hash=? AND expires>?"
		}
		a.Store.DB.QueryRow(query, hash, now()).Scan(&n)
		if n != 1 {
			finish("cancelled", "Link expired or already consumed", true)
			return
		}
	}
	if e = send(ctx, c, recipient, body, id); e != nil {
		state := "queued"
		if attempts >= 4 {
			state = "failed"
		}
		finish(state, "SMTP delivery failed; check connection, TLS and credentials", false)
		return
	}
	finish("sent", "Accepted by SMTP server", true)
}
func (a *App) sendMail(ctx context.Context, c MailSettings, to string, b mailBody, id int) error {
	return a.sendMailTLS(ctx, c, to, b, id, nil)
}
func (a *App) sendMailTLS(ctx context.Context, c MailSettings, to string, b mailBody, id int, tlsConfig *tls.Config) error {
	opts := []mail.Option{mail.WithPort(c.Port), mail.WithTimeout(20 * time.Second), mail.WithTLSPolicy(mail.TLSMandatory)}
	if tlsConfig != nil {
		opts = append(opts, mail.WithTLSConfig(tlsConfig))
	}
	if c.Mode == "tls" {
		opts = append(opts, mail.WithSSL())
	}
	if c.Username != "" {
		password, e := a.unseal("smtp", c.Password)
		if e != nil {
			return e
		}
		defer clear(password)
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(c.Username), mail.WithPassword(string(password)))
	}
	client, e := mail.NewClient(c.Host, opts...)
	if e != nil {
		return e
	}
	m := mail.NewMsg()
	if e = m.FromFormat(c.Name, c.Sender); e != nil {
		return e
	}
	if e = m.To(to); e != nil {
		return e
	}
	m.Subject(b.Subject)
	m.SetBodyString(mail.TypeTextPlain, b.Body)
	origin, _ := url.Parse(a.Config.BaseURL)
	m.SetMessageIDWithValue("waypoint-" + strconv.Itoa(id) + "@" + origin.Hostname())
	return client.DialAndSendWithContext(ctx, m)
}

package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/alexedwards/argon2id"
	"net/http"
	"strings"
	"time"
)

var ErrConflict = errors.New("This record changed or the action is no longer available. Reload and try again.")

func secret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func hashToken(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func passwordHash(p string) (string, error) {
	if len(p) < 12 || len(p) > 256 {
		return "", errors.New("Use a password between 12 and 256 characters.")
	}
	return argon2id.CreateHash(p, argon2id.DefaultParams)
}
func (s *Store) User(id int) *User {
	u := &User{}
	e := s.DB.QueryRow("SELECT id,username,email,role,enabled,generation FROM users WHERE id=?", id).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Enabled, &u.Generation)
	if e != nil {
		return nil
	}
	return u
}
func (a *App) current(r *http.Request) *User {
	id := a.Sessions.GetInt(r.Context(), "user")
	if id == 0 {
		return nil
	}
	u := a.Store.User(id)
	if u == nil || !u.Enabled || u.Generation != a.Sessions.GetInt(r.Context(), "generation") {
		a.Sessions.Destroy(r.Context())
		return nil
	}
	return u
}
func (s *Store) CreateAdmin(username, password string) error {
	if !validUsername(username) {
		return errors.New("Username must contain 3–40 letters, digits, dots, hyphens or underscores.")
	}
	h, e := passwordHash(password)
	if e != nil {
		return e
	}
	return s.Write(func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRow("SELECT count(*) FROM users WHERE role='admin' AND enabled=1").Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return errors.New("An administrator already exists; use the authenticated member editor or local recovery.")
		}
		r, e := tx.Exec("INSERT INTO users(username,password,role,created) VALUES(?,?,'admin',?)", username, h, now())
		if e != nil {
			return e
		}
		id, _ := r.LastInsertId()
		return audit(tx, 0, "bootstrap administrator", idTarget("user", int(id)))
	})
}
func (s *Store) Recover(username, password string) error {
	h, e := passwordHash(password)
	if e != nil {
		return e
	}
	return s.Write(func(tx *sql.Tx) error {
		var id int
		if e := tx.QueryRow("SELECT id FROM users WHERE username=? AND role='admin'", username).Scan(&id); e != nil {
			return errors.New("Administrator not found")
		}
		if _, e := tx.Exec("UPDATE users SET password=?,enabled=1,generation=generation+1 WHERE id=?", h, id); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE tokens SET consumed=? WHERE user_id=? AND consumed IS NULL", now(), id); e != nil {
			return e
		}
		return audit(tx, 0, "local administrator recovery", idTarget("user", id))
	})
}
func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func (s *Store) IssueToken(actor int, kind, username, email string, userID int, recommendations ...int) (string, error) {
	if kind != "invite" && kind != "reset" {
		return "", errors.New("Invalid token type")
	}
	if kind == "invite" && !validUsername(username) {
		return "", errors.New("Choose a valid username (3–40 letters, digits, dots, hyphens or underscores).")
	}
	t := secret()
	duration := 48 * time.Hour
	if kind == "reset" {
		duration = time.Hour
	}
	e := s.Write(func(tx *sql.Tx) error {
		var uid any
		if kind == "reset" {
			var enabled bool
			if e := tx.QueryRow("SELECT username,email,enabled FROM users WHERE id=?", userID).Scan(&username, &email, &enabled); e != nil || !enabled {
				return errors.New("Choose an enabled member.")
			}
			uid = userID
		} else {
			var n int
			tx.QueryRow("SELECT count(*) FROM users WHERE username=?", username).Scan(&n)
			if n > 0 {
				return errors.New("That username already exists.")
			}
		}
		if _, e := tx.Exec("UPDATE tokens SET consumed=? WHERE kind=? AND username=? AND consumed IS NULL", now(), kind, username); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO tokens(hash,kind,username,email,user_id,expires) VALUES(?,?,?,?,?,?)", hashToken(t), kind, username, email, uid, stamp(time.Now().Add(duration))); e != nil {
			return e
		}
		if kind == "invite" {
			if len(recommendations) > 12 {
				return errors.New("Recommend at most 12 services")
			}
			for _, sid := range recommendations {
				if _, e := tx.Exec("INSERT OR IGNORE INTO token_recommendations(token_hash,service_id) VALUES(?,?)", hashToken(t), sid); e != nil {
					return e
				}
			}
		}
		return audit(tx, actor, "issue "+kind, "membership")
	})
	return t, e
}
func (s *Store) Redeem(token, password string) error {
	h, e := passwordHash(password)
	if e != nil {
		return e
	}
	return s.Write(func(tx *sql.Tx) error {
		var kind, username, email string
		var uid sql.NullInt64
		if e := tx.QueryRow("SELECT kind,username,email,user_id FROM tokens WHERE hash=? AND consumed IS NULL AND expires>?", hashToken(token), now()).Scan(&kind, &username, &email, &uid); e != nil {
			return errors.New("This link is invalid, expired, or already used.")
		}
		if kind == "invite" {
			r, e := tx.Exec("INSERT INTO users(username,email,password,role,created) VALUES(?,?,?,'member',?)", username, email, h, now())
			if e != nil {
				return errors.New("This invitation cannot be redeemed.")
			}
			uid.Int64, _ = r.LastInsertId()
			if _, e := tx.Exec("INSERT INTO recommendations(user_id,service_id) SELECT ?,service_id FROM token_recommendations WHERE token_hash=?", uid.Int64, hashToken(token)); e != nil {
				return e
			}
		} else {
			res, e := tx.Exec("UPDATE users SET password=?,generation=generation+1 WHERE id=? AND enabled=1", h, uid.Int64)
			if e != nil {
				return e
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return errors.New("Account unavailable")
			}
		}
		res, e := tx.Exec("UPDATE tokens SET consumed=? WHERE hash=? AND consumed IS NULL", now(), hashToken(token))
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		return audit(tx, int(uid.Int64), "redeem "+kind, "membership")
	})
}
func (s *Store) Limited(key string, max int, window time.Duration) bool {
	allowed := false
	e := s.Write(func(tx *sql.Tx) error {
		t := time.Now().Unix()
		_, e := tx.Exec("INSERT INTO limits(key,count,reset) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset<=? THEN 1 ELSE count+1 END,reset=CASE WHEN reset<=? THEN excluded.reset ELSE reset END", key, t+int64(window.Seconds()), t, t)
		if e != nil {
			return e
		}
		var n int
		e = tx.QueryRow("SELECT count FROM limits WHERE key=?", key).Scan(&n)
		allowed = n <= max
		return e
	})
	return e != nil || !allowed
}
func (a *App) auth(w http.ResponseWriter, r *http.Request) {
	p := a.page(r, "Account", "auth")
	kind := r.PathValue("action")
	if kind == "" {
		kind = "login"
	}
	p.AdminTab = kind
	if !includes([]string{"login", "redeem", "password", "logout"}, kind) {
		a.fail(w, r, 404, "Account page unavailable")
		return
	}
	if kind == "password" && p.User == nil {
		http.Redirect(w, r, "/account/login", 303)
		return
	}
	if kind == "redeem" {
		p.TokenURL = r.URL.Query().Get("token")
		if p.TokenURL != "" {
			a.Store.DB.QueryRow("SELECT username FROM tokens WHERE hash=? AND consumed IS NULL AND expires>?", hashToken(p.TokenURL), now()).Scan(&p.Query)
		}
	}
	if r.Method == "GET" {
		if kind == "login" {
			p.Query = a.Sessions.PopString(r.Context(), "suggested_username")
		}
		a.render(w, r, p)
		return
	}
	if kind != "logout" && a.Store.Limited("auth:"+a.clientIP(r), 20, 15*time.Minute) {
		a.fail(w, r, 429, "Too many attempts. Please try again in 15 minutes.")
		return
	}
	var err error
	switch kind {
	case "login":
		var id int
		var h string
		err = a.Store.DB.QueryRow("SELECT id,password FROM users WHERE username=? AND enabled=1", strings.TrimSpace(r.FormValue("username"))).Scan(&id, &h)
		if err == nil {
			var ok bool
			ok, err = argon2id.ComparePasswordAndHash(r.FormValue("password"), h)
			if !ok {
				err = errors.New("Invalid username or password.")
			}
		}
		if err == nil {
			u := a.Store.User(id)
			a.Sessions.RenewToken(r.Context())
			a.Sessions.Put(r.Context(), "user", id)
			a.Sessions.Put(r.Context(), "generation", u.Generation)
			http.Redirect(w, r, "/", 303)
			return
		}
		err = errors.New("Invalid username or password.")
	case "redeem":
		err = a.Store.Redeem(r.FormValue("token"), r.FormValue("password"))
		if err == nil {
			var username string
			a.Store.DB.QueryRow("SELECT username FROM tokens WHERE hash=?", hashToken(r.FormValue("token"))).Scan(&username)
			a.Sessions.Put(r.Context(), "suggested_username", username)
			http.Redirect(w, r, "/account/login?success=Account+ready.+You+can+sign+in.", 303)
			return
		}
	case "logout":
		a.Sessions.Destroy(r.Context())
		http.Redirect(w, r, "/account/login", 303)
		return
	case "password":
		if p.User == nil {
			a.fail(w, r, 403, "Sign in to change your password.")
			return
		}
		var h string
		a.Store.DB.QueryRow("SELECT password FROM users WHERE id=?", p.User.ID).Scan(&h)
		ok, _ := argon2id.ComparePasswordAndHash(r.FormValue("current_password"), h)
		if !ok {
			err = errors.New("Current password is incorrect.")
		} else {
			h, err = passwordHash(r.FormValue("password"))
			if err == nil {
				err = a.Store.Write(func(tx *sql.Tx) error {
					_, e := tx.Exec("UPDATE users SET password=?,generation=generation+1 WHERE id=?", h, p.User.ID)
					if e != nil {
						return e
					}
					_, e = tx.Exec("UPDATE tokens SET consumed=? WHERE user_id=? AND consumed IS NULL", now(), p.User.ID)
					if e != nil {
						return e
					}
					return audit(tx, p.User.ID, "change password", "account")
				})
				if err == nil {
					a.Sessions.Destroy(r.Context())
					http.Redirect(w, r, "/account/login?success=Password+changed.+Sign+in+again.", 303)
					return
				}
			}
		}
	default:
		err = errors.New("Unknown account action")
	}
	p.Error = fmt.Sprint(err)
	w.WriteHeader(400)
	a.render(w, r, p)
}

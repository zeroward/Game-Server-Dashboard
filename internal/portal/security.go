package portal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type SecurityPage struct {
	Pending, Enroll, TOTP, Recent, Verified, Notify bool
	Secret, Email                                   string
	Keys                                            [][]string
	Codes                                           []string
}

func (a *App) initSecurity() error {
	dir := a.Config.SecretsDir
	if dir == "" {
		dir = filepath.Join(a.Config.DataDir, "secrets")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(dir, "account.key")
	key, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		var n int
		if e = a.Store.DB.QueryRow(`SELECT (SELECT count(*) FROM account_security WHERE totp IS NOT NULL)+(SELECT count(*) FROM mail_settings WHERE password IS NOT NULL)+(SELECT count(*) FROM mail_outbox WHERE payload IS NOT NULL)+(SELECT count(*) FROM auth_challenges WHERE payload IS NOT NULL)`).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return errors.New("Account encryption key missing; restore the portal-secrets volume")
		}
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return e
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		return errors.New("Invalid account encryption key")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	a.secretCipher, e = cipher.NewGCMWithRandomNonce(block)
	if e != nil {
		return e
	}
	origin, _ := url.Parse(a.Config.BaseURL)
	a.WebAuthn, e = webauthn.New(&webauthn.Config{RPDisplayName: "Waypoint", RPID: origin.Hostname(), RPOrigins: []string{strings.TrimRight(a.Config.BaseURL, "/")}})
	return e
}
func (a *App) seal(purpose string, b []byte) []byte {
	return a.secretCipher.Seal(nil, nil, b, []byte(purpose))
}
func (a *App) unseal(purpose string, b []byte) ([]byte, error) {
	return a.secretCipher.Open(nil, nil, b, []byte(purpose))
}
func (a *App) factors(id int) (bool, int) {
	var enabled bool
	var n int
	a.Store.DB.QueryRow("SELECT totp IS NOT NULL FROM account_security WHERE user_id=?", id).Scan(&enabled)
	a.Store.DB.QueryRow("SELECT count(*) FROM passkeys WHERE user_id=?", id).Scan(&n)
	return enabled, n
}
func (a *App) securityUser(r *http.Request) *User {
	if u := a.current(r); u != nil {
		return u
	}
	id := a.Sessions.GetInt(r.Context(), "pending_user")
	u := a.Store.User(id)
	if u == nil || !u.Enabled || u.Generation != a.Sessions.GetInt(r.Context(), "pending_generation") || a.Sessions.GetInt64(r.Context(), "pending_until") < time.Now().Unix() {
		return nil
	}
	return u
}
func (a *App) pending(r *http.Request, u *User, mode string) error {
	if e := a.Sessions.RenewToken(r.Context()); e != nil {
		return e
	}
	a.Sessions.Remove(r.Context(), "user")
	a.Sessions.Remove(r.Context(), "mfa")
	a.Sessions.Put(r.Context(), "pending_user", u.ID)
	a.Sessions.Put(r.Context(), "pending_generation", u.Generation)
	a.Sessions.Put(r.Context(), "pending_until", time.Now().Add(10*time.Minute).Unix())
	a.Sessions.Put(r.Context(), "pending_mode", mode)
	return nil
}
func (a *App) signedIn(r *http.Request, u *User) error {
	fresh := a.Store.User(u.ID)
	if fresh == nil || !fresh.Enabled || fresh.Generation != u.Generation {
		return ErrConflict
	}
	if e := a.Sessions.RenewToken(r.Context()); e != nil {
		return e
	}
	a.Sessions.Remove(r.Context(), "pending_user")
	a.Sessions.Remove(r.Context(), "pending_mode")
	a.Sessions.Put(r.Context(), "user", u.ID)
	a.Sessions.Put(r.Context(), "generation", u.Generation)
	a.Sessions.Put(r.Context(), "mfa", true)
	a.Sessions.Put(r.Context(), "recent", time.Now().Unix())
	return nil
}
func (a *App) recent(r *http.Request) bool {
	return a.current(r) != nil && time.Now().Unix()-a.Sessions.GetInt64(r.Context(), "recent") < 300
}
func (a *App) challenge(r *http.Request, u *User, purpose string, payload []byte) error {
	key := "challenge_" + purpose
	id := secret()
	uid, gen := any(nil), 0
	if u != nil {
		uid = u.ID
		gen = u.Generation
	}
	e := a.Store.Write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM auth_challenges WHERE id=? OR expires<=?", hashToken(a.Sessions.GetString(r.Context(), key)), now()); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO auth_challenges(id,user_id,generation,purpose,payload,expires) VALUES(?,?,?,?,?,?)", hashToken(id), uid, gen, purpose, a.seal("challenge:"+purpose, payload), stamp(time.Now().Add(5*time.Minute)))
		return e
	})
	if e == nil {
		a.Sessions.Put(r.Context(), key, id)
	}
	return e
}
func (a *App) takeChallenge(r *http.Request, u *User, purpose string) ([]byte, error) {
	var b []byte
	id := hashToken(a.Sessions.PopString(r.Context(), "challenge_"+purpose))
	e := a.Store.Write(func(tx *sql.Tx) error {
		var uid sql.NullInt64
		var gen int
		if e := tx.QueryRow("SELECT user_id,generation,payload FROM auth_challenges WHERE id=? AND purpose=? AND expires>?", id, purpose, now()).Scan(&uid, &gen, &b); e != nil {
			return errors.New("This security step expired. Start again.")
		}
		if u != nil && (!uid.Valid || int(uid.Int64) != u.ID || gen != u.Generation) {
			return ErrConflict
		}
		_, e := tx.Exec("DELETE FROM auth_challenges WHERE id=?", id)
		return e
	})
	if e != nil {
		return nil, e
	}
	return a.unseal("challenge:"+purpose, b)
}
func securityIdentity(tx *sql.Tx, u *User) error {
	var gen int
	if e := tx.QueryRow("SELECT generation FROM users WHERE id=? AND enabled=1", u.ID).Scan(&gen); e != nil || gen != u.Generation {
		return ErrConflict
	}
	return nil
}
func ensureSecurity(tx *sql.Tx, id int) error {
	_, e := tx.Exec("INSERT OR IGNORE INTO account_security(user_id,handle) VALUES(?,?)", id, []byte(secret()))
	return e
}
func (a *App) checkTOTP(u *User, code string) error {
	return a.Store.Write(func(tx *sql.Tx) error {
		if e := securityIdentity(tx, u); e != nil {
			return e
		}
		var encrypted []byte
		var last int64
		if e := tx.QueryRow("SELECT totp,last_step FROM account_security WHERE user_id=? AND totp IS NOT NULL", u.ID).Scan(&encrypted, &last); e != nil {
			return errors.New("Invalid authenticator code")
		}
		b, e := a.unseal(fmt.Sprint("totp:", u.ID), encrypted)
		if e != nil {
			return e
		}
		defer clear(b)
		step, e := validStep(string(b), code, last)
		if e != nil {
			return e
		}
		_, e = tx.Exec("UPDATE account_security SET last_step=? WHERE user_id=?", step, u.ID)
		return e
	})
}
func validStep(key, code string, last int64) (int64, error) {
	step := time.Now().Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		s := step + offset
		if s <= last {
			continue
		}
		ok, e := totp.ValidateCustom(code, key, time.Unix(s*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && ok {
			return s, nil
		}
	}
	return 0, errors.New("Invalid or already used authenticator code. Try the next code.")
}
func newCodes(tx *sql.Tx, u *User) ([]string, error) {
	if _, e := tx.Exec("DELETE FROM recovery_codes WHERE user_id=?", u.ID); e != nil {
		return nil, e
	}
	codes := []string{}
	for i := 0; i < 10; i++ {
		c := secret()[:24]
		if _, e := tx.Exec("INSERT INTO recovery_codes(hash,user_id) VALUES(?,?)", hashToken(c), u.ID); e != nil {
			return nil, e
		}
		codes = append(codes, c)
	}
	return codes, nil
}
func clearFactors(tx *sql.Tx, id int) error {
	for _, q := range []string{"DELETE FROM passkeys WHERE user_id=?", "DELETE FROM recovery_codes WHERE user_id=?", "DELETE FROM auth_challenges WHERE user_id=?", "DELETE FROM email_tokens WHERE user_id=?", "UPDATE account_security SET totp=NULL,last_step=-1 WHERE user_id=?", "UPDATE tokens SET consumed=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=? AND consumed IS NULL", "UPDATE users SET generation=generation+1 WHERE id=?"} {
		if _, e := tx.Exec(q, id); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) recoveryLogin(r *http.Request) error {
	var id, generation int
	var u *User
	e := a.Store.Write(func(tx *sql.Tx) error {
		if e := tx.QueryRow("SELECT u.id,u.generation FROM recovery_codes c JOIN users u ON u.id=c.user_id WHERE c.hash=? AND u.username=? AND u.enabled=1", hashToken(strings.TrimSpace(r.FormValue("code"))), strings.TrimSpace(r.FormValue("username"))).Scan(&id, &generation); e != nil {
			return errors.New("Invalid recovery details")
		}
		if e := clearFactors(tx, id); e != nil {
			return e
		}
		return audit(tx, id, "recovery code used; factors reset", idTarget("user", id))
	})
	if e != nil {
		return e
	}
	u = a.Store.User(id)
	if u == nil || !u.Enabled || u.Generation != generation+1 {
		return ErrConflict
	}
	return a.pending(r, u, "enroll")
}
func (a *App) security(w http.ResponseWriter, r *http.Request) {
	u := a.securityUser(r)
	if u == nil {
		http.Redirect(w, r, "/account/login", 303)
		return
	}
	p := a.page(r, "Account security", "security")
	sp := &SecurityPage{}
	p.Security = sp
	sp.Pending = a.current(r) == nil
	sp.Enroll = sp.Pending && a.Sessions.GetString(r.Context(), "pending_mode") == "enroll"
	var e error
	if r.Method == "POST" {
		if a.Store.Limited(fmt.Sprint("security:", u.ID), 30, 15*time.Minute) {
			a.fail(w, r, 429, "Too many security attempts. Try again later.")
			return
		}
		action := r.FormValue("action")
		if includes([]string{"totp-remove", "key-remove", "codes"}, action) && r.FormValue("confirm") != "on" {
			e = errors.New("Confirm this security change before continuing")
		} else if sp.Enroll && !includes([]string{"totp-start", "totp-confirm"}, action) {
			e = errors.New("Enroll a login method first")
		} else if sp.Pending && !sp.Enroll && action != "verify" {
			e = errors.New("Complete sign-in first")
		} else if !sp.Pending && !a.recent(r) && action != "reauth" {
			e = errors.New("Confirm your identity below before changing security settings")
		} else {
			switch action {
			case "verify":
				e = a.checkTOTP(u, r.FormValue("code"))
				if e == nil {
					e = a.signedIn(r, u)
					if e == nil {
						http.Redirect(w, r, "/", 303)
						return
					}
				}
			case "reauth":
				var h string
				a.Store.DB.QueryRow("SELECT password FROM users WHERE id=?", u.ID).Scan(&h)
				ok, _ := argon2id.ComparePasswordAndHash(r.FormValue("password"), h)
				if !ok {
					e = errors.New("Invalid password or authenticator code")
				} else {
					e = a.checkTOTP(u, r.FormValue("code"))
				}
				if e == nil {
					a.Sessions.Put(r.Context(), "recent", time.Now().Unix())
				}
			case "totp-start":
				var key *otp.Key
				key, e = totp.Generate(totp.GenerateOpts{Issuer: a.Store.Settings().Name, AccountName: u.Username})
				if e == nil {
					e = a.challenge(r, u, "totp", []byte(key.URL()))
				}
			case "totp-confirm":
				var raw []byte
				raw, e = a.takeChallenge(r, u, "totp")
				if e == nil {
					var key *otp.Key
					key, e = otp.NewKeyFromURL(string(raw))
					if e == nil {
						var step int64
						step, e = validStep(key.Secret(), r.FormValue("code"), -1)
						if e == nil {
							e = a.Store.Write(func(tx *sql.Tx) error {
								if e := securityIdentity(tx, u); e != nil {
									return e
								}
								if e := ensureSecurity(tx, u.ID); e != nil {
									return e
								}
								if _, e := tx.Exec("UPDATE account_security SET totp=?,last_step=? WHERE user_id=?", a.seal(fmt.Sprint("totp:", u.ID), []byte(key.Secret())), step, u.ID); e != nil {
									return e
								}
								var err error
								sp.Codes, err = newCodes(tx, u)
								if err != nil {
									return err
								}
								if _, e := tx.Exec("UPDATE users SET generation=generation+1 WHERE id=?", u.ID); e != nil {
									return e
								}
								return audit(tx, u.ID, "enroll authenticator", idTarget("user", u.ID))
							})
						}
					}
				}
				if e == nil {
					e = a.signedIn(r, nextGeneration(u))
					sp.Pending = false
					sp.Enroll = false
				}
			case "totp-remove":
				e = a.Store.Write(func(tx *sql.Tx) error {
					if e := securityIdentity(tx, u); e != nil {
						return e
					}
					var n int
					tx.QueryRow("SELECT count(*) FROM passkeys WHERE user_id=?", u.ID).Scan(&n)
					if n == 0 {
						return errors.New("Add a passkey before removing your authenticator")
					}
					if _, e := tx.Exec("UPDATE account_security SET totp=NULL,last_step=-1 WHERE user_id=?", u.ID); e != nil {
						return e
					}
					return securityMutation(tx, u, "remove authenticator")
				})
			case "key-remove":
				key, err := base64.RawURLEncoding.DecodeString(r.FormValue("key"))
				e = err
				if e == nil {
					e = a.Store.Write(func(tx *sql.Tx) error {
						if e := securityIdentity(tx, u); e != nil {
							return e
						}
						var n int
						tx.QueryRow("SELECT (SELECT count(*) FROM passkeys WHERE user_id=?)+(SELECT count(*) FROM account_security WHERE user_id=? AND totp IS NOT NULL)", u.ID, u.ID).Scan(&n)
						if n < 2 {
							return errors.New("Add another login method before removing your last passkey")
						}
						res, e := tx.Exec("DELETE FROM passkeys WHERE id=? AND user_id=?", key, u.ID)
						if e != nil {
							return e
						}
						n64, _ := res.RowsAffected()
						if n64 != 1 {
							return ErrConflict
						}
						return securityMutation(tx, u, "remove passkey")
					})
				}
			case "codes":
				e = a.Store.Write(func(tx *sql.Tx) error {
					if e := securityIdentity(tx, u); e != nil {
						return e
					}
					var err error
					sp.Codes, err = newCodes(tx, u)
					if err != nil {
						return err
					}
					return securityMutation(tx, u, "regenerate recovery codes")
				})
			case "email":
				e = a.updateEmail(r, u)
			default:
				e = errors.New("Unknown security action")
			}
		}
		if e == nil && includes([]string{"totp-remove", "key-remove", "codes"}, action) {
			e = a.signedIn(r, nextGeneration(u))
		}
		if e != nil {
			p.Error = e.Error()
		} else {
			p.Success = "Account security updated."
		}
	}
	sp.TOTP, _ = a.factors(u.ID)
	sp.Recent = a.recent(r)
	a.Store.DB.QueryRow("SELECT email,email_verified,email_notifications FROM users WHERE id=?", u.ID).Scan(&sp.Email, &sp.Verified, &sp.Notify)
	rows, err := a.Store.DB.Query("SELECT id,name,created,coalesce(used,'Never') FROM passkeys WHERE user_id=? ORDER BY created", u.ID)
	if err == nil {
		for rows.Next() {
			var b []byte
			var name, created, used string
			rows.Scan(&b, &name, &created, &used)
			sp.Keys = append(sp.Keys, []string{base64.RawURLEncoding.EncodeToString(b), name, created, used})
		}
		rows.Close()
	}
	if raw, err := a.peekTOTP(r, u); err == nil {
		if key, err := otp.NewKeyFromURL(string(raw)); err == nil {
			sp.Secret = key.Secret()
		}
	}
	p.User = a.current(r)
	a.render(w, r, p)
}
func securityMutation(tx *sql.Tx, u *User, action string) error {
	if _, e := tx.Exec("UPDATE users SET generation=generation+1 WHERE id=?", u.ID); e != nil {
		return e
	}
	return audit(tx, u.ID, action, idTarget("user", u.ID))
}
func (a *App) peekTOTP(r *http.Request, u *User) ([]byte, error) {
	var b []byte
	e := a.Store.DB.QueryRow("SELECT payload FROM auth_challenges WHERE id=? AND user_id=? AND generation=? AND purpose='totp' AND expires>?", hashToken(a.Sessions.GetString(r.Context(), "challenge_totp")), u.ID, u.Generation, now()).Scan(&b)
	if e != nil {
		return nil, e
	}
	return a.unseal("challenge:totp", b)
}
func (a *App) totpQR(w http.ResponseWriter, r *http.Request) {
	u := a.securityUser(r)
	if u == nil {
		a.fail(w, r, 404, "Unavailable")
		return
	}
	raw, e := a.peekTOTP(r, u)
	if e != nil {
		a.fail(w, r, 404, "Setup expired")
		return
	}
	key, e := otp.NewKeyFromURL(string(raw))
	if e != nil {
		a.fail(w, r, 404, "Unavailable")
		return
	}
	img, e := key.Image(256, 256)
	if e != nil {
		a.fail(w, r, 500, "Could not render code")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	png.Encode(w, img)
}

func nextGeneration(u *User) *User { next := *u; next.Generation++; return &next }

package portal

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyUser struct {
	*User
	Handle      []byte
	Credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.Handle }
func (u *passkeyUser) WebAuthnName() string                       { return u.Username }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.Username }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (a *App) passkeyUser(u *User) (*passkeyUser, error) {
	if u == nil || !u.Enabled {
		return nil, errors.New("Account unavailable")
	}
	pu := &passkeyUser{User: u}
	if e := a.Store.Write(func(tx *sql.Tx) error {
		if e := securityIdentity(tx, u); e != nil {
			return e
		}
		return ensureSecurity(tx, u.ID)
	}); e != nil {
		return nil, e
	}
	if e := a.Store.DB.QueryRow("SELECT handle FROM account_security WHERE user_id=?", u.ID).Scan(&pu.Handle); e != nil {
		return nil, e
	}
	rows, e := a.Store.DB.Query("SELECT credential FROM passkeys WHERE user_id=? AND rp_id=?", u.ID, a.WebAuthn.Config.RPID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var c webauthn.Credential
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		pu.Credentials = append(pu.Credentials, c)
	}
	return pu, rows.Err()
}

type ceremony struct {
	Session webauthn.SessionData
	Name    string
}

func (a *App) passkey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	fail := func() {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Passkey operation failed or expired. Try again, or use another login method."})
	}
	if a.Store.Limited("passkey:"+a.clientIP(r), 50, 15*time.Minute) {
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]string{"error": "Too many attempts. Try again later."})
		return
	}
	action := r.PathValue("action")
	u := a.securityUser(r)
	register := strings.HasPrefix(action, "register-")
	if register && (u == nil || !(a.recent(r) || (a.current(r) == nil && a.Sessions.GetString(r.Context(), "pending_mode") == "enroll"))) {
		fail()
		return
	}
	var pu *passkeyUser
	var e error
	if register {
		pu, e = a.passkeyUser(u)
		if e != nil {
			fail()
			return
		}
	}
	switch action {
	case "register-begin":
		var in struct{ Name string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(strings.TrimSpace(in.Name)) == 0 || len(in.Name) > 80 {
			fail()
			return
		}
		if len(pu.Credentials) >= 20 {
			fail()
			return
		}
		options, session, err := a.WebAuthn.BeginRegistration(pu, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}), webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
		if err != nil {
			fail()
			return
		}
		b, _ := json.Marshal(ceremony{*session, strings.TrimSpace(in.Name)})
		if a.challenge(r, u, "register", b) != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(options)
	case "register-finish":
		b, err := a.takeChallenge(r, u, "register")
		if err != nil {
			fail()
			return
		}
		var c ceremony
		if json.Unmarshal(b, &c) != nil {
			fail()
			return
		}
		cred, err := a.WebAuthn.FinishRegistration(pu, c.Session, r)
		if err != nil {
			fail()
			return
		}
		raw, _ := json.Marshal(cred)
		var codes []string
		err = a.Store.Write(func(tx *sql.Tx) error {
			if e := securityIdentity(tx, u); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO passkeys(id,user_id,rp_id,credential,name,created) VALUES(?,?,?,?,?,?)", cred.ID, u.ID, a.WebAuthn.Config.RPID, raw, c.Name, now()); e != nil {
				return e
			}
			var n int
			if e := tx.QueryRow("SELECT count(*) FROM recovery_codes WHERE user_id=?", u.ID).Scan(&n); e != nil {
				return e
			}
			if n == 0 {
				var e error
				codes, e = newCodes(tx, u)
				if e != nil {
					return e
				}
			}
			if _, e := tx.Exec("UPDATE users SET generation=generation+1 WHERE id=?", u.ID); e != nil {
				return e
			}
			return audit(tx, u.ID, "enroll passkey", idTarget("user", u.ID))
		})
		if err != nil {
			fail()
			return
		}
		if a.signedIn(r, nextGeneration(u)) != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"redirect": "/account/security", "codes": codes})
	case "login-begin":
		options, session, err := a.WebAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			fail()
			return
		}
		b, _ := json.Marshal(ceremony{Session: *session})
		if a.challenge(r, u, "passkey-login", b) != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(options)
	case "login-finish":
		b, err := a.takeChallenge(r, u, "passkey-login")
		if err != nil {
			fail()
			return
		}
		var c ceremony
		if json.Unmarshal(b, &c) != nil {
			fail()
			return
		}
		var found *passkeyUser
		var previous []byte
		cred, err := a.WebAuthn.FinishDiscoverableLogin(func(rawID, handle []byte) (webauthn.User, error) {
			var id int
			if err := a.Store.DB.QueryRow("SELECT user_id,credential FROM passkeys WHERE id=? AND rp_id=?", rawID, a.WebAuthn.Config.RPID).Scan(&id, &previous); err != nil {
				return nil, err
			}
			if u != nil && u.ID != id {
				return nil, ErrConflict
			}
			found, e = a.passkeyUser(a.Store.User(id))
			if e != nil {
				return nil, e
			}
			if !bytes.Equal(found.Handle, handle) {
				return nil, ErrConflict
			}
			return found, nil
		}, c.Session, r)
		if err != nil || found == nil || cred.Authenticator.CloneWarning {
			fail()
			return
		}
		raw, _ := json.Marshal(cred)
		err = a.Store.Write(func(tx *sql.Tx) error {
			if e := securityIdentity(tx, found.User); e != nil {
				return e
			}
			res, e := tx.Exec("UPDATE passkeys SET credential=?,used=? WHERE id=? AND user_id=? AND credential=?", raw, now(), cred.ID, found.ID, previous)
			if e != nil {
				return e
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return ErrConflict
			}
			return nil
		})
		if err != nil || a.signedIn(r, found.User) != nil {
			fail()
			return
		}
		redirect := "/"
		if u != nil && a.current(r) != nil {
			redirect = "/account/security"
		}
		json.NewEncoder(w).Encode(map[string]string{"redirect": redirect})
	default:
		fail()
	}
}

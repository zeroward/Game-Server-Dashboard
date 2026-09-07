package portal

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

func (s *Store) Requests(u *User) []Request {
	if u == nil {
		return nil
	}
	q := "SELECT r.id,r.user_id,r.service_id,r.service_name,u.username,r.kind,r.state,r.reason,r.fields,r.requested_end,r.created,r.updated,r.version FROM requests r JOIN users u ON u.id=r.user_id"
	args := []any{}
	if u.Role != "admin" {
		q += " WHERE r.user_id=?"
		args = append(args, u.ID)
	}
	q += " ORDER BY r.id DESC"
	rows, e := s.DB.Query(q, args...)
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Request
	for rows.Next() {
		var v Request
		var f string
		rows.Scan(&v.ID, &v.UserID, &v.ServiceID, &v.ServiceName, &v.Username, &v.Kind, &v.State, &v.Reason, &f, &v.RequestedEnd, &v.Created, &v.Updated, &v.Version)
		json.Unmarshal([]byte(f), &v.Fields)
		all = append(all, v)
	}
	return all
}
func (s *Store) request(u *User, id int) *Request {
	for _, v := range s.Requests(u) {
		if v.ID == id {
			return &v
		}
	}
	return nil
}
func (s *Store) Messages(id int, private bool) []Message {
	table := "messages"
	if private {
		table = "private_notes"
	}
	rows, e := s.DB.Query("SELECT m.id,u.username,m.body,m.created FROM "+table+" m JOIN users u ON u.id=m.actor_id WHERE request_id=? ORDER BY m.id", id)
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Message
	for rows.Next() {
		var v Message
		rows.Scan(&v.ID, &v.Actor, &v.Body, &v.Created)
		all = append(all, v)
	}
	return all
}
func (s *Store) History(id int) []Transition {
	rows, e := s.DB.Query("SELECT u.username,t.from_state,t.to_state,t.created FROM transitions t JOIN users u ON u.id=t.actor_id WHERE request_id=? ORDER BY t.id", id)
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Transition
	for rows.Next() {
		var v Transition
		rows.Scan(&v.Actor, &v.From, &v.To, &v.Created)
		all = append(all, v)
	}
	return all
}
func notify(tx *sql.Tx, user, request, access int, text string) error {
	_, e := tx.Exec("INSERT INTO notifications(user_id,request_id,access_id,text,created) VALUES(?,?,?,?,?)", user, nullable(request), nullable(access), text, now())
	return e
}
func notifyAdmins(tx *sql.Tx, request int, text string) error {
	_, e := tx.Exec("INSERT INTO notifications(user_id,request_id,text,created) SELECT id,?,?,? FROM users WHERE role='admin' AND enabled=1", nullable(request), text, now())
	return e
}
func activeState(kind, state string) bool {
	if kind == "access" {
		return state == "Pending" || state == "Needs Information" || state == "Approved - Setup Pending"
	}
	return state == "Open" || state == "Waiting for Member"
}
func actions(r *Request, admin bool) []string {
	if !activeState(r.Kind, r.State) {
		return nil
	}
	if !admin {
		return []string{"Cancelled"}
	}
	if r.Kind == "support" {
		if r.State == "Open" {
			return []string{"Waiting for Member", "Resolved", "Cancelled"}
		}
		return []string{"Open", "Resolved", "Cancelled"}
	}
	switch r.State {
	case "Pending":
		return []string{"Needs Information", "Approved - Setup Pending", "Denied", "Cancelled"}
	case "Needs Information":
		return []string{"Pending", "Approved - Setup Pending", "Denied", "Cancelled"}
	case "Approved - Setup Pending":
		return []string{"Needs Information", "Fulfilled", "Denied", "Cancelled"}
	}
	return nil
}
func includes(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}
func dateInput(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	t, e := time.Parse("2006-01-02", v)
	if e != nil {
		return "", errors.New("Use a valid end date.")
	}
	t = t.Add(24 * time.Hour)
	if !t.After(time.Now()) {
		return "", errors.New("End date must be in the future.")
	}
	return stamp(t), nil
}
func (s *Store) Submit(u *User, v *Service, kind, reason, end string, values map[string]string) (int, error) {
	if u == nil || !u.Enabled || !s.discover(u, v) {
		return 0, errors.New("Service unavailable")
	}
	if kind != "access" && kind != "support" {
		return 0, errors.New("Invalid request type")
	}
	if kind == "access" && (v.Mode != "request" || s.hasAccess(u, v.ID)) {
		return 0, errors.New("This service does not need a new access request.")
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 || len(reason) > 4000 {
		return 0, errors.New("Provide a reason between 3 and 4,000 characters.")
	}
	var fields []Value
	requestedEnd := ""
	if kind == "access" {
		for _, f := range v.Config.Fields {
			value := strings.TrimSpace(values[f.Key])
			if f.Required && value == "" {
				return 0, fmt.Errorf("%s is required", f.Label)
			}
			max := 300
			if f.Type == "long" {
				max = 2000
			}
			if len(value) > max {
				return 0, fmt.Errorf("%s is too long", f.Label)
			}
			if value != "" && f.Type == "email" {
				if addr, e := mail.ParseAddress(value); e != nil || addr.Address != value {
					return 0, fmt.Errorf("%s must be an email address", f.Label)
				}
			}
			if value != "" && f.Type == "select" && !includes(f.Options, value) {
				return 0, fmt.Errorf("Choose a listed option for %s", f.Label)
			}
			fields = append(fields, Value{f.Label, value})
		}
		if v.Config.Duration {
			var e error
			requestedEnd, e = dateInput(end)
			if e != nil {
				return 0, e
			}
		}
	}
	b, _ := json.Marshal(fields)
	state := "Pending"
	if kind == "support" {
		state = "Open"
	}
	var id int
	e := s.Write(func(tx *sql.Tx) error {
		var published, archived bool
		if e := tx.QueryRow("SELECT published,archived FROM services WHERE id=?", v.ID).Scan(&published, &archived); e != nil || !published || archived {
			return errors.New("This service is no longer accepting requests.")
		}
		res, e := tx.Exec("INSERT INTO requests(user_id,service_id,service_name,kind,state,reason,fields,requested_end,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)", u.ID, v.ID, v.Name, kind, state, reason, string(b), requestedEnd, now(), now())
		if e != nil {
			if strings.Contains(e.Error(), "UNIQUE") {
				return errors.New("You already have an active access request for this service.")
			}
			return e
		}
		n, _ := res.LastInsertId()
		id = int(n)
		if _, e = tx.Exec("INSERT INTO transitions(request_id,actor_id,from_state,to_state,created) VALUES(?,?,'',?,?)", id, u.ID, state, now()); e != nil {
			return e
		}
		if e = notifyAdmins(tx, id, "A new request needs review."); e != nil {
			return e
		}
		return audit(tx, u.ID, "submit "+kind, idTarget("request", id))
	})
	return id, e
}
func (s *Store) Reply(u *User, id, version int, body string, private bool) error {
	r := s.request(u, id)
	if r == nil {
		return errors.New("Request unavailable")
	}
	if private && u.Role != "admin" {
		return errors.New("Administrator permission required")
	}
	body = strings.TrimSpace(body)
	if len(body) < 1 || len(body) > 6000 {
		return errors.New("Write a message between 1 and 6,000 characters.")
	}
	if !private && !activeState(r.Kind, r.State) {
		return errors.New("This request is closed. Create a new request for further help.")
	}
	return s.Write(func(tx *sql.Tx) error {
		res, e := tx.Exec("UPDATE requests SET version=version+1,updated=? WHERE id=? AND version=?", now(), id, version)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		table := "messages"
		if private {
			table = "private_notes"
		}
		if _, e := tx.Exec("INSERT INTO "+table+"(request_id,actor_id,body,created) VALUES(?,?,?,?)", id, u.ID, body, now()); e != nil {
			return e
		}
		if !private {
			if u.Role == "admin" {
				if e = notify(tx, r.UserID, id, 0, "There is a new reply to your request."); e != nil {
					return e
				}
			} else {
				if e = notifyAdmins(tx, id, "A member replied to a request."); e != nil {
					return e
				}
				target := ""
				if r.State == "Needs Information" {
					target = "Pending"
				}
				if r.State == "Waiting for Member" {
					target = "Open"
				}
				if target != "" {
					if _, e = tx.Exec("UPDATE requests SET state=? WHERE id=?", target, id); e != nil {
						return e
					}
					if _, e = tx.Exec("INSERT INTO transitions(request_id,actor_id,from_state,to_state,created) VALUES(?,?,?,?,?)", id, u.ID, r.State, target, now()); e != nil {
						return e
					}
				}
			}
		}
		act := "reply"
		if private {
			act = "private note"
		}
		return audit(tx, u.ID, act, idTarget("request", id))
	})
}
func (s *Store) Transition(u *User, id, version int, target, explanation, nextSteps, expires string, confirmed bool) error {
	r := s.request(u, id)
	if r == nil {
		return errors.New("Request unavailable")
	}
	if !includes(actions(r, u.Role == "admin"), target) {
		return errors.New("That state transition is not allowed.")
	}
	if (target == "Denied" || target == "Needs Information" || target == "Waiting for Member") && strings.TrimSpace(explanation) == "" {
		return errors.New("A member-visible explanation is required.")
	}
	if len(explanation) > 6000 || len(nextSteps) > 6000 {
		return errors.New("Keep text under 6,000 characters.")
	}
	if target == "Fulfilled" && (!confirmed || strings.TrimSpace(nextSteps) == "") {
		return errors.New("Confirm external setup and provide non-secret next steps before fulfillment.")
	}
	expiry, e := dateInput(expires)
	if e != nil {
		return e
	}
	return s.Write(func(tx *sql.Tx) error {
		res, e := tx.Exec("UPDATE requests SET state=?,updated=?,version=version+1 WHERE id=? AND version=? AND state=?", target, now(), id, version, r.State)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		if explanation != "" {
			if _, e = tx.Exec("INSERT INTO messages(request_id,actor_id,body,created) VALUES(?,?,?,?)", id, u.ID, explanation, now()); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("INSERT INTO transitions(request_id,actor_id,from_state,to_state,created) VALUES(?,?,?,?,?)", id, u.ID, r.State, target, now()); e != nil {
			return e
		}
		if target == "Fulfilled" {
			if _, e = grant(tx, u.ID, r.UserID, r.ServiceID, nextSteps, expiry); e != nil {
				return e
			}
		}
		if e = notify(tx, r.UserID, id, 0, "Your request status has changed."); e != nil {
			return e
		}
		if u.Role != "admin" {
			if e = notifyAdmins(tx, id, "A member updated a request."); e != nil {
				return e
			}
		}
		return audit(tx, u.ID, "request state: "+target, idTarget("request", id))
	})
}
func grant(tx *sql.Tx, actor, user, service int, steps, expiry string) (int, error) {
	var enabled, published, archived bool
	var serviceName string
	if e := tx.QueryRow("SELECT enabled FROM users WHERE id=?", user).Scan(&enabled); e != nil || !enabled {
		return 0, errors.New("Cannot grant portal access to a disabled member.")
	}
	if e := tx.QueryRow("SELECT published,archived,name FROM services WHERE id=?", service).Scan(&published, &archived, &serviceName); e != nil || !published || archived {
		return 0, errors.New("Publish the service before recording access.")
	}
	_, e := tx.Exec("INSERT INTO access_records(user_id,service_id,service_name,state,granted,expires,next_steps) VALUES(?,?,?,'active',?,?,?) ON CONFLICT(user_id,service_id) DO UPDATE SET state='active',service_name=excluded.service_name,granted=excluded.granted,expires=excluded.expires,next_steps=excluded.next_steps,version=access_records.version+1", user, service, serviceName, now(), expiry, steps)
	if e != nil {
		return 0, e
	}
	var id int
	tx.QueryRow("SELECT id FROM access_records WHERE user_id=? AND service_id=?", user, service).Scan(&id)
	if e = notify(tx, user, 0, id, "Your portal access record has been updated."); e != nil {
		return 0, e
	}
	if e = accessHistory(tx, actor, id); e != nil {
		return 0, e
	}
	return id, audit(tx, actor, "record active access", idTarget("access", id))
}
func (s *Store) Accesses(u *User) []Access {
	if u == nil {
		return nil
	}
	q := "SELECT a.id,a.user_id,a.service_id,u.username,a.service_name,a.state,a.granted,a.expires,a.next_steps,a.version FROM access_records a JOIN users u ON u.id=a.user_id JOIN services s ON s.id=a.service_id"
	args := []any{}
	if u.Role != "admin" {
		q += " WHERE a.user_id=?"
		args = append(args, u.ID)
	}
	q += " ORDER BY a.id DESC"
	rows, e := s.DB.Query(q, args...)
	if e != nil {
		return nil
	}
	var all []Access
	for rows.Next() {
		var v Access
		rows.Scan(&v.ID, &v.UserID, &v.ServiceID, &v.Username, &v.ServiceName, &v.State, &v.Granted, &v.Expires, &v.NextSteps, &v.Version)
		if v.State == "active" && v.Expires != "" && v.Expires <= now() {
			v.State = "expired"
		}
		all = append(all, v)
	}
	rows.Close()
	for i := range all {
		v := s.service(all[i].ServiceID)
		if v != nil {
			all[i].Service = s.permitted(u, *v)
		}
		if all[i].State != "active" || all[i].Service == nil || !all[i].Service.Details {
			all[i].NextSteps = ""
		}
	}
	return all
}
func (s *Store) Reconcile() error {
	return s.Write(func(tx *sql.Tx) error {
		if e := expireVPN(tx); e != nil {
			return e
		}
		rows, e := tx.Query("SELECT a.id,a.user_id FROM access_records a JOIN users u ON u.id=a.user_id WHERE a.state='active' AND a.expires<>'' AND a.expires<=?", now())
		if e != nil {
			return e
		}
		var ids [][2]int
		for rows.Next() {
			var x [2]int
			rows.Scan(&x[0], &x[1])
			ids = append(ids, x)
		}
		rows.Close()
		for _, x := range ids {
			if _, e = tx.Exec("UPDATE access_records SET state='expired',version=version+1 WHERE id=?", x[0]); e != nil {
				return e
			}
			if _, e = tx.Exec("INSERT OR IGNORE INTO followups(access_id,reason,created) VALUES(?,'Portal access expired; remove external permissions manually.',?)", x[0], now()); e != nil {
				return e
			}
			if e = notify(tx, x[1], 0, x[0], "Your portal access record has expired."); e != nil {
				return e
			}
			if e = accessHistory(tx, 0, x[0]); e != nil {
				return e
			}
			if e = audit(tx, 0, "portal access expired", idTarget("access", x[0])); e != nil {
				return e
			}
		}
		_, e = tx.Exec("DELETE FROM sessions WHERE expiry<?", time.Now().Unix())
		if e != nil {
			return e
		}
		_, e = tx.Exec("DELETE FROM limits WHERE reset<?", time.Now().Add(-24*time.Hour).Unix())
		return e
	})
}
func (a *App) requests(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	p := a.page(r, "My requests", "requests")
	owner := *u
	owner.Role = "member"
	p.Requests = a.Store.Requests(&owner)
	a.render(w, r, p)
}
func (a *App) submitRequest(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	if a.Store.Limited(fmt.Sprintf("submit:%d", u.ID), 10, time.Hour) {
		a.fail(w, r, 429, "Request limit reached. Try again later.")
		return
	}
	v := a.findService(r.PathValue("slug"))
	if v == nil || !a.Store.discover(u, v) {
		a.fail(w, r, 404, "Service unavailable")
		return
	}
	values := map[string]string{}
	for _, f := range v.Config.Fields {
		values[f.Key] = r.FormValue("field_" + f.Key)
	}
	id, e := a.Store.Submit(u, v, r.FormValue("kind"), r.FormValue("reason"), r.FormValue("end"), values)
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), 303)
}
func (a *App) requestDetail(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	v := a.Store.request(u, number(r.PathValue("id")))
	if v == nil {
		a.fail(w, r, 404, "Request unavailable")
		return
	}
	p := a.page(r, fmt.Sprintf("Request #%d", v.ID), "request")
	p.Request = v
	p.Messages = a.Store.Messages(v.ID, false)
	p.History = a.Store.History(v.ID)
	p.Actions = actions(v, u.Role == "admin")
	if u.Role == "admin" {
		p.Notes = a.Store.Messages(v.ID, true)
	}
	a.render(w, r, p)
}
func (a *App) requestAction(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	if r.PathValue("action") == "note" && u.Role != "admin" {
		a.fail(w, r, 403, "Private notes are for administrators only.")
		return
	}
	id := number(r.PathValue("id"))
	if a.Store.request(u, id) == nil {
		a.fail(w, r, 404, "Request unavailable")
		return
	}
	if a.Store.Limited(fmt.Sprintf("reply:%d", u.ID), 60, time.Hour) {
		a.fail(w, r, 429, "Too many updates. Please try later.")
		return
	}
	var e error
	switch r.PathValue("action") {
	case "reply", "note":
		e = a.Store.Reply(u, id, number(r.FormValue("version")), r.FormValue("body"), r.PathValue("action") == "note")
	case "transition":
		e = a.Store.Transition(u, id, number(r.FormValue("version")), r.FormValue("state"), r.FormValue("explanation"), r.FormValue("next_steps"), r.FormValue("expires"), r.FormValue("confirmed") == "on")
	default:
		e = errors.New("Unknown action")
	}
	if e != nil {
		code := 400
		if errors.Is(e, ErrConflict) {
			code = 409
		}
		a.fail(w, r, code, e.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), 303)
}
func (a *App) myAccess(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	p := a.page(r, "My access", "access")
	owner := *u
	owner.Role = "member"
	p.Accesses = a.Store.Accesses(&owner)
	for _, req := range a.Store.Requests(&owner) {
		if req.Kind == "access" && activeState(req.Kind, req.State) {
			p.Requests = append(p.Requests, req)
		}
	}
	for _, v := range a.Store.AllServices() {
		if v.Mode == "external" {
			if pview := a.Store.permitted(u, v); pview != nil {
				p.Services = append(p.Services, *pview)
			}
		}
	}
	a.render(w, r, p)
}
func (a *App) visibleNotifications(u *User, unread bool) []Notification {
	q := "SELECT id,coalesce(request_id,0),coalesce(access_id,0),coalesce(device_id,0),text,created,read_at IS NOT NULL FROM notifications WHERE user_id=?"
	if unread {
		q += " AND read_at IS NULL"
	}
	q += " ORDER BY id DESC LIMIT 100"
	rows, e := a.Store.DB.Query(q, u.ID)
	if e != nil {
		return nil
	}
	var all []Notification
	for rows.Next() {
		var n Notification
		rows.Scan(&n.ID, &n.RequestID, &n.AccessID, &n.DeviceID, &n.Text, &n.Created, &n.Read)
		all = append(all, n)
	}
	rows.Close()
	var visible []Notification
	for _, n := range all {
		if n.DeviceID != 0 {
			var owner int
			if !a.Config.VPNEnabled || a.Store.DB.QueryRow("SELECT user_id FROM vpn_devices WHERE id=?", n.DeviceID).Scan(&owner) != nil || (u.Role != "admin" && owner != u.ID) {
				continue
			}
		}
		if n.RequestID != 0 && a.Store.request(u, n.RequestID) == nil {
			continue
		}
		if n.AccessID != 0 {
			found := false
			for _, v := range a.Store.Accesses(u) {
				if v.ID == n.AccessID {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		visible = append(visible, n)
	}
	return visible
}
func (a *App) notifications(w http.ResponseWriter, r *http.Request) {
	u := a.member(w, r)
	if u == nil {
		return
	}
	if r.Method == "POST" {
		a.Store.DB.Exec("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL", now(), u.ID)
		http.Redirect(w, r, "/notifications", 303)
		return
	}
	p := a.page(r, "Notifications", "notifications")
	p.Notifications = a.visibleNotifications(u, false)
	a.render(w, r, p)
}

func accessHistory(tx *sql.Tx, actor, id int) error {
	_, e := tx.Exec("INSERT INTO access_history(access_id,actor_id,state,granted,expires,created) SELECT id,?,state,granted,expires,? FROM access_records WHERE id=?", nullable(actor), now(), id)
	return e
}

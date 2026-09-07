package portal

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func (s *Store) Users() []User {
	rows, e := s.DB.Query("SELECT id,username,email,role,enabled,generation FROM users ORDER BY username")
	if e != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Enabled, &u.Generation)
		out = append(out, u)
	}
	return out
}
func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	u := a.administrator(w, r)
	if u == nil {
		return
	}
	a.Store.Reconcile()
	section := r.PathValue("section")
	if section == "" {
		section = "requests"
	}
	p := a.page(r, "Administration", "admin")
	p.AdminTab = section
	p.Categories = a.Store.Categories()
	p.Services = a.Store.AllServices()
	id := number(r.PathValue("id"))
	p.Query = r.URL.Query().Get("q")
	p.Filter = r.URL.Query().Get("state")
	switch section {
	case "services":
		if r.PathValue("id") != "" {
			v := a.Store.service(id)
			if r.PathValue("id") == "new" {
				v = &Service{Audience: "member", DetailsAudience: "access", Mode: "info", Config: ServiceConfig{Type: "application", FocalX: 50, FocalY: 50, Status: "Unknown"}}
			}
			if v == nil {
				a.fail(w, r, 404, "Service unavailable")
				return
			}
			p.Service = v
			p.Links = a.Store.AllLinks()
		}
	case "preview":
		v := a.Store.service(id)
		if v == nil {
			a.fail(w, r, 404, "Service unavailable")
			return
		}
		persona := r.URL.Query().Get("as")
		var viewer *User
		switch persona {
		case "member":
			viewer = &User{ID: -1, Role: "member", Enabled: true}
		case "access":
			viewer = &User{ID: -1, Role: "member", Enabled: true}
		case "public":
		default:
			persona = "public"
		}
		p.Preview = persona
		p.View = "preview"
		if persona == "access" {
			sid := v.AccessService
			if sid == 0 {
				sid = v.ID
			}
			viewer = &User{ID: -1, Role: "member", Enabled: true, PreviewService: sid}
		}

		p.Service = a.Store.permitted(viewer, *v)
		p.GlobalLinks = a.Store.LinksFor(viewer, "global", 0)
		p.Announcements = a.Store.announcements(viewer, "service", v.ID)
	case "categories":
		for _, v := range p.Categories {
			if v.ID == id {
				p.Category = &v
			}
		}
		if r.PathValue("id") == "new" {
			p.Category = &Category{Audience: "member"}
		}
	case "links":
		p.Links = a.Store.AllLinks()
		for _, v := range p.Links {
			if v.ID == id {
				p.Link = &v
			}
		}
		if r.PathValue("id") == "new" {
			p.Link = &Link{Placement: "global", Audience: "member", Enabled: true, NewTab: true, Style: "secondary", Icon: "link"}
		}
	case "announcements":
		p.Announcements = a.Store.AllAnnouncements()
		for _, v := range p.Announcements {
			if v.ID == id {
				p.Announcement = &v
			}
		}
		if r.PathValue("id") == "new" {
			p.Announcement = &Announcement{Placement: "global", Audience: "member", Enabled: true}
		}
	case "members":
		p.Users = a.Store.Users()
		p.Rows = a.queryRows("SELECT username,kind,expires FROM tokens WHERE consumed IS NULL AND expires>strftime('%Y-%m-%dT%H:%M:%SZ','now') ORDER BY expires DESC")
		if id != 0 {
			p.EditUser = a.Store.User(id)
		}
	case "requests":
		for _, v := range a.Store.Requests(u) {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s", v.ID, v.Username, v.ServiceName, v.Reason, v.Kind))
			if p.Query != "" && !strings.Contains(hay, strings.ToLower(p.Query)) {
				continue
			}
			if p.Filter != "" && p.Filter != v.State {
				continue
			}
			p.Requests = append(p.Requests, v)
		}
	case "access":
		p.Users = a.Store.Users()
		p.Accesses = a.Store.Accesses(u)
		p.Rows = a.queryRows("SELECT h.access_id,u.username,h.state,h.granted,h.expires,h.created FROM access_history h LEFT JOIN users u ON u.id=h.actor_id ORDER BY h.id DESC LIMIT 100")
	case "followups":
		p.Rows = a.queryRows("SELECT f.id,u.username,s.name,f.reason,f.created,coalesce(f.completed,'') FROM followups f JOIN access_records a ON a.id=f.access_id JOIN users u ON u.id=a.user_id JOIN services s ON s.id=a.service_id ORDER BY f.completed IS NOT NULL,f.id DESC")
	case "audit":
		p.Rows = a.queryRows("SELECT a.id,coalesce(u.username,'local/system'),a.action,a.target,a.created FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 500")
	case "settings":
	default:
		a.fail(w, r, 404, "Administration page unavailable")
		return
	}
	a.render(w, r, p)
}
func (a *App) queryRows(query string) [][]string {
	rows, e := a.Store.DB.Query(query)
	if e != nil {
		return nil
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]string
	for rows.Next() {
		v := make([]string, len(cols))
		ptr := make([]any, len(cols))
		for i := range v {
			ptr[i] = &v[i]
		}
		rows.Scan(ptr...)
		out = append(out, v)
	}
	return out
}
func audienceValid(s string) bool {
	return includes([]string{"public", "member", "access", "admin"}, s)
}
func (a *App) validateAudience(au string, access int) error {
	if !audienceValid(au) {
		return errors.New("Choose a valid audience.")
	}
	if au == "access" && a.Store.service(access) == nil {
		return errors.New("Access audience requires an associated service.")
	}
	if access != 0 && a.Store.service(access) == nil {
		return errors.New("Associated service does not exist.")
	}
	return nil
}
func parseTime(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	t, e := time.Parse("2006-01-02T15:04", v)
	if e != nil {
		t, e = time.Parse(time.RFC3339, v)
	}
	if e != nil {
		return "", errors.New("Enter a valid UTC date and time.")
	}
	return stamp(t), nil
}
func (a *App) adminPost(w http.ResponseWriter, r *http.Request) {
	u := a.administrator(w, r)
	if u == nil {
		return
	}
	id := number(r.PathValue("id"))
	section := r.PathValue("section")
	action := r.FormValue("action")
	var e error
	redirect := "/admin/" + section
	if section == "artwork" {
		a.upload(w, r, u, id)
		return
	}
	switch section {
	case "services":
		if action == "archive" || action == "delete" {
			e = a.destroyService(u, id, action, r.FormValue("confirm") == "on")
		} else {
			var sid int
			sid, e = a.saveService(u, id, r)
			if e == nil {
				redirect = fmt.Sprintf("/admin/services/%d", sid)
			}
		}
	case "categories":
		e = a.saveCategory(u, id, r)
	case "links":
		e = a.saveLink(u, id, r)
	case "announcements":
		e = a.saveAnnouncement(u, id, r)
	case "settings":
		e = a.saveSettings(u, r)
	case "members":
		e = a.saveMember(u, id, r)
	case "revoke-token":
		if r.FormValue("confirm") != "on" {
			e = errors.New("Confirm invitation/recovery link revocation")
		} else {
			e = a.Store.Write(func(tx *sql.Tx) error {
				_, e := tx.Exec("UPDATE tokens SET consumed=? WHERE username=? AND kind=? AND consumed IS NULL", now(), r.FormValue("username"), r.FormValue("kind"))
				if e != nil {
					return e
				}
				return audit(tx, u.ID, "revoke delivery link", "membership")
			})
		}
		redirect = "/admin/members"
	case "invite", "reset":
		kind := section
		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		if email != "" {
			addr, err := mail.ParseAddress(email)
			if err != nil || addr.Address != email {
				e = errors.New("Enter a valid email address.")
			}
		}
		if e == nil {
			var token string
			var recommendations []int
			for _, raw := range r.Form["recommend"] {
				recommendations = append(recommendations, number(raw))
			}
			var delivery func(*sql.Tx, string, string, int) error
			if r.FormValue("delivery") == "email" {
				delivery = func(tx *sql.Tx, token, to string, uid int) error {
					return a.queueMail(tx, uid, kind, to, hashToken(token), mailBody{"Your Waypoint " + kind, "You have received a Waypoint " + kind + " link. Set your password, then complete secure sign-in setup.\n\n" + a.Config.BaseURL + "/account/redeem?token=" + token})
				}
			}
			token, e = a.Store.issueToken(u.ID, kind, username, email, number(r.FormValue("user_id")), delivery, recommendations...)
			if e == nil {
				if delivery != nil {
					http.Redirect(w, r, "/admin/email?success=Email+queued", 303)
					return
				}
				p := a.page(r, "Delivery link", "token")
				p.TokenURL = a.Config.BaseURL + "/account/redeem?token=" + token
				a.render(w, r, p)
				return
			}
		}
	case "access":
		e = a.saveAccess(u, r)
	case "followups":
		if r.FormValue("confirm") != "on" {
			e = errors.New("Confirm that external removal was performed.")
		} else {
			e = a.Store.Write(func(tx *sql.Tx) error {
				res, e := tx.Exec("UPDATE followups SET completed=?,actor_id=? WHERE id=? AND completed IS NULL", now(), u.ID, id)
				if e != nil {
					return e
				}
				n, _ := res.RowsAffected()
				if n != 1 {
					return ErrConflict
				}
				return audit(tx, u.ID, "record manual external removal", idTarget("followup", id))
			})
		}
	default:
		e = errors.New("Unknown administration action")
	}
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	http.Redirect(w, r, redirect+"?success=Saved", 303)
}
func (a *App) saveService(u *User, id int, r *http.Request) (int, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	slug := r.FormValue("slug")
	if name == "" || len(name) > 120 || !slugPattern.MatchString(slug) || len(slug) > 100 {
		return 0, errors.New("Provide a name and a lowercase URL slug using letters, numbers, and hyphens.")
	}
	aud, details := r.FormValue("audience"), r.FormValue("details_audience")
	if !audienceValid(aud) || !audienceValid(details) {
		return 0, errors.New("Invalid audience")
	}
	sid := number(r.FormValue("access_service"))
	if sid != 0 && a.Store.service(sid) == nil {
		return 0, errors.New("Associated access service does not exist")
	}
	cat := number(r.FormValue("category_id"))
	if cat != 0 {
		found := false
		for _, c := range a.Store.Categories() {
			if c.ID == cat {
				found = true
			}
		}
		if !found {
			return 0, errors.New("Category does not exist")
		}
	}
	mode := r.FormValue("mode")
	if !includes([]string{"info", "request", "external"}, mode) {
		return 0, errors.New("Invalid access mode")
	}
	c := ServiceConfig{ExternalPortalURL: strings.TrimSpace(r.FormValue("external_portal_url")), ExternalPortalLabel: strings.TrimSpace(r.FormValue("external_portal_label")), ExternalPortalAudience: r.FormValue("external_portal_audience"), ExternalPortalNewTab: r.FormValue("external_portal_new_tab") == "on", Type: r.FormValue("type"), Game: r.FormValue("game"), Summary: r.FormValue("summary"), Description: r.FormValue("description"), Tags: r.FormValue("tags"), Artwork: r.FormValue("artwork"), FocalX: number(r.FormValue("focal_x")), FocalY: number(r.FormValue("focal_y")), Host: r.FormValue("host"), Port: r.FormValue("port"), Version: r.FormValue("version"), Platform: r.FormValue("platform"), Connection: r.FormValue("connection"), Guide: r.FormValue("guide"), Status: r.FormValue("status"), DirectLink: number(r.FormValue("direct_link")), Duration: r.FormValue("duration") == "on"}
	if c.ExternalPortalAudience == "" {
		c.ExternalPortalAudience = "member"
	}
	if !audienceValid(c.ExternalPortalAudience) {
		return 0, errors.New("Invalid signup portal audience")
	}
	if len(c.ExternalPortalURL) > 2048 || len(c.ExternalPortalLabel) > 80 {
		return 0, errors.New("Signup portal URL or button label is too long")
	}
	if e := validURL(c.ExternalPortalURL, false); e != nil {
		return 0, fmt.Errorf("Signup portal: %w", e)
	}
	if !includes([]string{"game", "application", "network", "destination"}, c.Type) {
		return 0, errors.New("Invalid service type")
	}
	for label, value := range map[string]string{"game": c.Game, "hostname": c.Host, "version": c.Version, "platform": c.Platform} {
		if len(value) > 255 {
			return 0, fmt.Errorf("%s must be under 256 characters", label)
		}
	}
	if len(c.Connection) > 1000 || len(c.Artwork) > 2048 {
		return 0, errors.New("Connection string or artwork URL is too long")
	}
	if len(c.Summary) > 240 || len(c.Description) > 20000 || len(c.Guide) > 20000 || len(c.Tags) > 300 {
		return 0, errors.New("Description or tags exceed their length limit.")
	}
	if c.FocalX < 0 || c.FocalX > 100 || c.FocalY < 0 || c.FocalY > 100 {
		return 0, errors.New("Focal point must be between 0 and 100.")
	}
	if c.Port != "" {
		n, e := strconv.Atoi(c.Port)
		if e != nil || n < 1 || n > 65535 {
			return 0, errors.New("Port must be 1–65535.")
		}
	}
	if c.Artwork != "" {
		if strings.HasPrefix(c.Artwork, "/media/") {
			var parent sql.NullInt64
			e := a.Store.DB.QueryRow("SELECT service_id FROM media WHERE id=?", strings.TrimPrefix(c.Artwork, "/media/")).Scan(&parent)
			if e != nil || !parent.Valid || int(parent.Int64) != id {
				return 0, errors.New("Artwork must belong to this service")
			}
		} else if e := validURL(c.Artwork, false); e != nil {
			return 0, e
		}
	}
	if !includes([]string{"", "Unknown", "Online", "Offline", "Maintenance"}, c.Status) {
		return 0, errors.New("Invalid manual status")
	}
	old := a.Store.service(id)
	if old != nil {
		c.StatusAt = old.Config.StatusAt
	}
	if c.Status != "" && (old == nil || c.Status != old.Config.Status) {
		c.StatusAt = now()
	}
	if c.DirectLink != 0 {
		found := false
		for _, l := range a.Store.AllLinks() {
			if l.ID == c.DirectLink && l.Placement == "service" && l.ParentID == id {
				found = true
			}
		}
		if !found {
			return 0, errors.New("Choose a link belonging to this service for the direct card action.")
		}
	}
	for i := 0; i < 6; i++ {
		prefix := fmt.Sprintf("field_%d_", i)
		label := strings.TrimSpace(r.FormValue(prefix + "label"))
		if label == "" {
			continue
		}
		typ := r.FormValue(prefix + "type")
		if !includes([]string{"short", "long", "email", "select"}, typ) || len(label) > 100 {
			return 0, errors.New("Invalid request field")
		}
		f := Field{Key: fmt.Sprintf("f%d", i), Label: label, Type: typ, Required: r.FormValue(prefix+"required") == "on"}
		if typ == "select" {
			for _, v := range strings.Split(r.FormValue(prefix+"options"), ",") {
				v = strings.TrimSpace(v)
				if v != "" && len(v) < 100 {
					f.Options = append(f.Options, v)
				}
			}
			if len(f.Options) == 0 || len(f.Options) > 20 {
				return 0, errors.New("Select fields need 1–20 comma-separated options.")
			}
		}
		c.Fields = append(c.Fields, f)
	}
	for i := 0; i < 4; i++ {
		label := strings.TrimSpace(r.FormValue(fmt.Sprintf("custom_%d_label", i)))
		value := r.FormValue(fmt.Sprintf("custom_%d_value", i))
		if label != "" && value != "" {
			if len(label) > 100 || len(value) > 1000 {
				return 0, errors.New("Custom field is too long")
			}
			c.Custom = append(c.Custom, Value{label, value})
		}
	}
	b, _ := json.Marshal(c)
	e := a.Store.Write(func(tx *sql.Tx) error {
		args := []any{slug, name, nullable(cat), r.FormValue("published") == "on", aud, details, nullable(sid), mode, number(r.FormValue("position")), r.FormValue("featured") == "on", string(b)}
		if id == 0 {
			res, e := tx.Exec("INSERT INTO services(slug,name,category_id,published,audience,details_audience,access_service,mode,position,featured,config) VALUES(?,?,?,?,?,?,?,?,?,?,?)", args...)
			if e != nil {
				return e
			}
			n, _ := res.LastInsertId()
			id = int(n)
		} else {
			args = append(args, id)
			res, e := tx.Exec("UPDATE services SET slug=?,name=?,category_id=?,published=?,audience=?,details_audience=?,access_service=?,mode=?,position=?,featured=?,config=? WHERE id=? AND archived=0", args...)
			if e != nil {
				return e
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return errors.New("Archived services cannot be edited.")
			}
		}
		return audit(tx, u.ID, "save catalog and visibility", idTarget("service", id))
	})
	return id, e
}
func (a *App) destroyService(u *User, id int, action string, confirmed bool) error {
	if !confirmed {
		return errors.New("Confirm this destructive action.")
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		var n int
		tx.QueryRow("SELECT (SELECT count(*) FROM requests WHERE service_id=?)+(SELECT count(*) FROM access_records WHERE service_id=?)+(SELECT count(*) FROM links WHERE access_service=?)+(SELECT count(*) FROM services WHERE access_service=?)+(SELECT count(*) FROM categories WHERE access_service=?)+(SELECT count(*) FROM announcements WHERE access_service=?)+(SELECT count(*) FROM vpn_targets WHERE service_id=?)", id, id, id, id, id, id, id).Scan(&n)
		if action == "delete" && n == 0 { // Remove child configuration while preserving all historical references.
			for _, q := range []string{"DELETE FROM links WHERE placement='service' AND parent_id=?", "DELETE FROM announcements WHERE placement='service' AND parent_id=?", "DELETE FROM media WHERE service_id=?", "DELETE FROM services WHERE id=?"} {
				if _, e := tx.Exec(q, id); e != nil {
					return e
				}
			}
		} else {
			if _, e := tx.Exec("UPDATE services SET archived=1,published=0 WHERE id=?", id); e != nil {
				return e
			}
			action = "archive"
		}
		return audit(tx, u.ID, action, idTarget("service", id))
	})
}
func (a *App) saveCategory(u *User, id int, r *http.Request) error {
	if r.FormValue("action") == "delete" {
		if r.FormValue("confirm") != "on" {
			return errors.New("Confirm deletion")
		}
		return a.Store.Write(func(tx *sql.Tx) error {
			var n int
			tx.QueryRow("SELECT (SELECT count(*) FROM services WHERE category_id=?)+(SELECT count(*) FROM links WHERE placement='category' AND parent_id=?)+(SELECT count(*) FROM announcements WHERE placement='category' AND parent_id=?)", id, id, id).Scan(&n)
			if n > 0 {
				return errors.New("Reassign this category's services, links and announcements before deleting it.")
			}
			if _, e := tx.Exec("DELETE FROM categories WHERE id=?", id); e != nil {
				return e
			}
			return audit(tx, u.ID, "delete category", idTarget("category", id))
		})
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 80 {
		return errors.New("Category name is required (up to 80 characters).")
	}
	au := r.FormValue("audience")
	sid := number(r.FormValue("access_service"))
	if e := a.validateAudience(au, sid); e != nil {
		return e
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		var e error
		if id == 0 {
			res, err := tx.Exec("INSERT INTO categories(name,audience,access_service,position) VALUES(?,?,?,?)", name, au, nullable(sid), number(r.FormValue("position")))
			e = err
			if e == nil {
				n, _ := res.LastInsertId()
				id = int(n)
			}
		} else {
			_, e = tx.Exec("UPDATE categories SET name=?,audience=?,access_service=?,position=? WHERE id=?", name, au, nullable(sid), number(r.FormValue("position")), id)
		}
		if e != nil {
			return e
		}
		return audit(tx, u.ID, "save category and visibility", idTarget("category", id))
	})
}
func (a *App) validateParent(placement string, parent int) error {
	switch placement {
	case "global":
		if parent != 0 {
			return errors.New("Global placement has no parent")
		}
	case "service":
		if a.Store.service(parent) == nil {
			return errors.New("Choose an existing parent service")
		}
	case "category":
		found := false
		for _, c := range a.Store.Categories() {
			if c.ID == parent {
				found = true
			}
		}
		if !found {
			return errors.New("Choose an existing parent category")
		}
	default:
		return errors.New("Choose global, category or service placement")
	}
	return nil
}
func (a *App) saveLink(u *User, id int, r *http.Request) error {
	if r.FormValue("action") == "delete" {
		return a.deleteSimple(u, "links", id, r)
	}
	label, raw := strings.TrimSpace(r.FormValue("label")), r.FormValue("url")
	if label == "" || len(label) > 100 || len(raw) > 2048 || len(r.FormValue("description")) > 300 {
		return errors.New("Provide a short label and valid URL length")
	}
	placement, parent, access := r.FormValue("placement"), placementParent(r), number(r.FormValue("access_service"))
	if e := a.validateParent(placement, parent); e != nil {
		return e
	}
	if e := a.validateAudience(r.FormValue("audience"), access); e != nil {
		return e
	}
	if e := validURL(raw, placement == "service" && r.FormValue("icon") == "game"); e != nil {
		return e
	}
	if !includes([]string{"link", "game", "play", "book", "status", "download", "community"}, r.FormValue("icon")) {
		return errors.New("Choose a supported icon")
	}
	if !includes([]string{"primary", "secondary"}, r.FormValue("style")) {
		return errors.New("Choose primary action or secondary resource")
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		args := []any{label, raw, placement, nullable(parent), nullable(access), r.FormValue("audience"), number(r.FormValue("position")), r.FormValue("enabled") == "on", r.FormValue("style"), r.FormValue("new_tab") == "on", r.FormValue("icon"), r.FormValue("description")}
		if id == 0 {
			res, e := tx.Exec("INSERT INTO links(label,url,placement,parent_id,access_service,audience,position,enabled,style,new_tab,icon,description) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", args...)
			if e != nil {
				return e
			}
			n, _ := res.LastInsertId()
			id = int(n)
		} else {
			args = append(args, id)
			if _, e := tx.Exec("UPDATE links SET label=?,url=?,placement=?,parent_id=?,access_service=?,audience=?,position=?,enabled=?,style=?,new_tab=?,icon=?,description=? WHERE id=?", args...); e != nil {
				return e
			}
		}
		return audit(tx, u.ID, "save contextual link", idTarget("link", id))
	})
}
func (a *App) deleteSimple(u *User, table string, id int, r *http.Request) error {
	if r.FormValue("confirm") != "on" {
		return errors.New("Confirm deletion")
	}
	if table != "links" && table != "announcements" {
		return errors.New("Invalid target")
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM "+table+" WHERE id=?", id); e != nil {
			return e
		}
		return audit(tx, u.ID, "delete "+table, idTarget(table, id))
	})
}
func (a *App) saveAnnouncement(u *User, id int, r *http.Request) error {
	if r.FormValue("action") == "delete" {
		return a.deleteSimple(u, "announcements", id, r)
	}
	title, body := r.FormValue("title"), r.FormValue("body")
	if title == "" || len(title) > 120 || len(body) > 4000 {
		return errors.New("Provide a title and concise announcement (up to 4,000 characters).")
	}
	placement, parent, sid := r.FormValue("placement"), placementParent(r), number(r.FormValue("access_service"))
	if e := a.validateParent(placement, parent); e != nil {
		return e
	}
	if e := a.validateAudience(r.FormValue("audience"), sid); e != nil {
		return e
	}
	start, e := parseTime(r.FormValue("starts"))
	if e != nil {
		return e
	}
	end, e := parseTime(r.FormValue("ends"))
	if e != nil {
		return e
	}
	if start != "" && end != "" && start >= end {
		return errors.New("End must be after start")
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		args := []any{title, body, placement, nullable(parent), r.FormValue("audience"), nullable(sid), start, end, r.FormValue("enabled") == "on"}
		if id == 0 {
			res, e := tx.Exec("INSERT INTO announcements(title,body,placement,parent_id,audience,access_service,starts,ends,enabled) VALUES(?,?,?,?,?,?,?,?,?)", args...)
			if e != nil {
				return e
			}
			n, _ := res.LastInsertId()
			id = int(n)
		} else {
			args = append(args, id)
			if _, e := tx.Exec("UPDATE announcements SET title=?,body=?,placement=?,parent_id=?,audience=?,access_service=?,starts=?,ends=?,enabled=? WHERE id=?", args...); e != nil {
				return e
			}
		}
		return audit(tx, u.ID, "save announcement", idTarget("announcement", id))
	})
}
func (a *App) saveSettings(u *User, r *http.Request) error {
	name, description, accent := r.FormValue("name"), r.FormValue("description"), r.FormValue("accent")
	if name == "" || len(name) > 80 || len(description) > 300 {
		return errors.New("Provide a name and short description")
	}
	if len(accent) != 7 || accent[0] != '#' {
		return errors.New("Choose a hex accent color")
	}
	if _, e := hex.DecodeString(accent[1:]); e != nil {
		return e
	}
	logo := r.FormValue("logo")
	if logo != "" {
		if !strings.HasPrefix(logo, "/media/") {
			return errors.New("Upload a local logo first")
		}
		var parent sql.NullInt64
		e := a.Store.DB.QueryRow("SELECT service_id FROM media WHERE id=?", strings.TrimPrefix(logo, "/media/")).Scan(&parent)
		if e != nil || parent.Valid {
			return errors.New("Invalid logo")
		}
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		_, e := tx.Exec("UPDATE settings SET name=?,description=?,accent=?,public=?,logo=? WHERE id=1", name, description, accent, r.FormValue("public") == "on", logo)
		if e != nil {
			return e
		}
		return audit(tx, u.ID, "save dashboard settings", "settings")
	})
}
func (a *App) saveMember(actor *User, id int, r *http.Request) error {
	role := r.FormValue("role")
	enabled := r.FormValue("enabled") == "on"
	if role != "member" && role != "admin" {
		return errors.New("Invalid role")
	}
	if (!enabled || role == "member") && r.FormValue("confirm") != "on" {
		return errors.New("Confirm member permission changes")
	}
	return a.Store.Write(func(tx *sql.Tx) error {
		var oldRole string
		var oldEnabled bool
		if e := tx.QueryRow("SELECT role,enabled FROM users WHERE id=?", id).Scan(&oldRole, &oldEnabled); e != nil {
			return e
		}
		if oldRole == "admin" && oldEnabled && (!enabled || role != "admin") {
			var n int
			tx.QueryRow("SELECT count(*) FROM users WHERE role='admin' AND enabled=1").Scan(&n)
			if n <= 1 {
				return errors.New("The last usable administrator cannot be disabled or demoted.")
			}
		}
		if _, e := tx.Exec("UPDATE users SET role=?,enabled=?,generation=generation+1 WHERE id=?", role, enabled, id); e != nil {
			return e
		}
		if !enabled {
			if _, e := tx.Exec("UPDATE vpn_deliveries SET encrypted_key=NULL WHERE device_id IN (SELECT id FROM vpn_devices WHERE user_id=?)", id); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO vpn_history(grant_id,actor_id,state,cidr,protocol,ports,expires,created) SELECT g.id,?,'Revoked',g.cidr,g.protocol,g.ports,g.expires,? FROM vpn_grants g JOIN vpn_devices d ON d.id=g.device_id WHERE d.user_id=? AND g.state IN ('Pending','Approved')", actor.ID, now(), id); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE vpn_grants SET state='Revoked',explanation='Member disabled.',version=version+1 WHERE device_id IN (SELECT id FROM vpn_devices WHERE user_id=?) AND state IN ('Pending','Approved')", id); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE vpn_devices SET state='revoked',version=version+1 WHERE user_id=? AND state!='revoked'", id); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO notifications(user_id,device_id,text,created) SELECT u.id,d.id,'Disabled member: device revocation awaits gateway confirmation.',? FROM users u JOIN vpn_devices d ON d.user_id=? WHERE u.role='admin' AND u.enabled=1", now(), id); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE tokens SET consumed=? WHERE user_id=? AND consumed IS NULL", now(), id); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT OR IGNORE INTO followups(access_id,reason,created) SELECT id,'Member disabled; remove external permissions manually.',? FROM access_records WHERE user_id=? AND state='active'", now(), id); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO access_history(access_id,actor_id,state,granted,expires,created) SELECT id,?,'revoked',granted,expires,? FROM access_records WHERE user_id=? AND state='active'", actor.ID, now(), id); e != nil {
				return e
			}
			if _, e := tx.Exec("UPDATE access_records SET state='revoked',version=version+1 WHERE user_id=? AND state='active'", id); e != nil {
				return e
			}
		}
		return audit(tx, actor.ID, "member role/status change", idTarget("user", id))
	})
}
func (a *App) saveAccess(u *User, r *http.Request) error {
	action := r.FormValue("action")
	if r.FormValue("confirm") != "on" {
		return errors.New("Confirm the manual access change")
	}
	if action == "grant" {
		steps := strings.TrimSpace(r.FormValue("next_steps"))
		if steps == "" || len(steps) > 6000 {
			return errors.New("Provide non-secret next steps (up to 6,000 characters).")
		}
		expiry, e := dateInput(r.FormValue("expires"))
		if e != nil {
			return e
		}
		return a.Store.Write(func(tx *sql.Tx) error {
			var currentVersion int
			err := tx.QueryRow("SELECT version FROM access_records WHERE user_id=? AND service_id=?", number(r.FormValue("user_id")), number(r.FormValue("service_id"))).Scan(&currentVersion)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if currentVersion != number(r.FormValue("version")) {
				return errors.New("An access record already exists or changed. Use its Update form below after reloading.")
			}
			_, e := grant(tx, u.ID, number(r.FormValue("user_id")), number(r.FormValue("service_id")), steps, expiry)
			return e
		})
	}
	if action != "revoke" && action != "expire" {
		return errors.New("Invalid access action")
	}
	id := number(r.FormValue("access_id"))
	return a.Store.Write(func(tx *sql.Tx) error {
		state := "revoked"
		if action == "expire" {
			state = "expired"
		}
		res, e := tx.Exec("UPDATE access_records SET state=?,version=version+1 WHERE id=? AND version=? AND state='active'", state, id, number(r.FormValue("version")))
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO followups(access_id,reason,created) VALUES(?,?,?)", id, "Portal record "+state+"; remove external permissions manually.", now()); e != nil {
			return e
		}
		var uid int
		tx.QueryRow("SELECT user_id FROM access_records WHERE id=?", id).Scan(&uid)
		if e = notify(tx, uid, 0, id, "Your portal access record has changed."); e != nil {
			return e
		}
		if e = accessHistory(tx, u.ID, id); e != nil {
			return e
		}
		return audit(tx, u.ID, "access "+state, idTarget("access", id))
	})
}

func placementParent(r *http.Request) int {
	placement := r.FormValue("placement")
	if placement == "global" {
		return 0
	}
	if placement == "category" && r.Form.Has("parent_category") {
		return number(r.FormValue("parent_category"))
	}
	if placement == "service" && r.Form.Has("parent_service") {
		return number(r.FormValue("parent_service"))
	}
	return number(r.FormValue("parent_id"))
}

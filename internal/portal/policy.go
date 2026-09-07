package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"html/template"
	"net/url"
	"strings"
)

func (s *Store) Settings() Settings {
	v := Settings{}
	s.DB.QueryRow("SELECT name,description,accent,public,logo FROM settings WHERE id=1").Scan(&v.Name, &v.Description, &v.Accent, &v.Public, &v.Logo)
	return v
}
func (s *Store) hasAccess(u *User, service int) bool {
	if u == nil || !u.Enabled {
		return false
	}
	if u.ID == -1 && u.PreviewService == service {
		return true
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM access_records WHERE user_id=? AND service_id=? AND state='active' AND (expires='' OR expires>?)", u.ID, service, now()).Scan(&n)
	return n > 0
}
func (s *Store) audience(u *User, audience string, service int) bool {
	if u != nil && u.Enabled && u.Role == "admin" {
		return true
	}
	switch audience {
	case "public":
		return u != nil && u.Enabled || s.Settings().Public
	case "member":
		return u != nil && u.Enabled
	case "access":
		return s.hasAccess(u, service)
	}
	return false
}
func (s *Store) Categories() []Category {
	rows, e := s.DB.Query("SELECT id,name,audience,coalesce(access_service,0),position FROM categories ORDER BY position,name")
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Category
	for rows.Next() {
		var c Category
		rows.Scan(&c.ID, &c.Name, &c.Audience, &c.AccessService, &c.Position)
		all = append(all, c)
	}
	return all
}
func (s *Store) categoryAllowed(u *User, id int) bool {
	if id == 0 {
		return true
	}
	var au string
	var sid int
	e := s.DB.QueryRow("SELECT audience,coalesce(access_service,0) FROM categories WHERE id=?", id).Scan(&au, &sid)
	return e == nil && s.audience(u, au, sid)
}
func (s *Store) AllServices() []Service {
	rows, e := s.DB.Query("SELECT id,slug,name,coalesce(category_id,0),published,archived,audience,details_audience,coalesce(access_service,0),mode,position,featured,config FROM services ORDER BY featured DESC,position,name")
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Service
	for rows.Next() {
		var v Service
		var config string
		rows.Scan(&v.ID, &v.Slug, &v.Name, &v.CategoryID, &v.Published, &v.Archived, &v.Audience, &v.DetailsAudience, &v.AccessService, &v.Mode, &v.Position, &v.Featured, &config)
		json.Unmarshal([]byte(config), &v.Config)
		all = append(all, v)
	}
	return all
}
func (s *Store) service(id int) *Service {
	for _, v := range s.AllServices() {
		if v.ID == id {
			return &v
		}
	}
	return nil
}
func (s *Store) discover(u *User, v *Service) bool {
	if v == nil {
		return false
	}
	if u != nil && u.Enabled && u.Role == "admin" {
		return true
	}
	sid := v.AccessService
	if sid == 0 {
		sid = v.ID
	}
	return v.Published && !v.Archived && s.categoryAllowed(u, v.CategoryID) && s.audience(u, v.Audience, sid)
}
func (s *Store) permitted(u *User, v Service) *Service {
	if !s.discover(u, &v) {
		return nil
	}
	sid := v.AccessService
	if sid == 0 {
		sid = v.ID
	}
	v.Details = s.audience(u, v.DetailsAudience, sid)
	v.Supportable = u != nil && u.Enabled && v.Published && !v.Archived
	v.Requestable = u != nil && u.Enabled && v.Mode == "request" && v.Published && !v.Archived && !s.hasAccess(u, v.ID)
	if v.Requestable {
		var active int
		s.DB.QueryRow("SELECT count(*) FROM requests WHERE user_id=? AND service_id=? AND kind='access' AND state IN ('Pending','Needs Information','Approved - Setup Pending')", u.ID, v.ID).Scan(&active)
		v.Requestable = active == 0
	}
	if !v.Details {
		v.Config.Host = ""
		v.Config.Port = ""
		v.Config.Version = ""
		v.Config.Platform = ""
		v.Config.Connection = ""
		v.Config.Custom = nil
		v.Config.Guide = ""
	}
	if u != nil {
		var n int
		s.DB.QueryRow("SELECT count(*) FROM recommendations WHERE user_id=? AND service_id=?", u.ID, v.ID).Scan(&n)
		v.Recommended = n > 0
	}
	v.ExternalPortal = nil
	if v.Mode == "external" && v.Config.ExternalPortalURL != "" {
		audience := v.Config.ExternalPortalAudience
		if audience == "" {
			audience = "member"
		}
		label := v.Config.ExternalPortalLabel
		if label == "" {
			label = "Open signup portal"
		}
		link := Link{URL: v.Config.ExternalPortalURL, Label: label, Placement: "service", ParentID: v.ID, AccessService: sid, Audience: audience, Enabled: true, Style: "primary", NewTab: v.Config.ExternalPortalNewTab}
		if validURL(link.URL, false) == nil && s.linkAllowed(u, link) {
			v.ExternalPortal = &link
		}
	}
	// Never retain a restricted destination or its label in a member-facing record.
	v.Config.ExternalPortalURL = ""
	v.Config.ExternalPortalLabel = ""
	v.Config.ExternalPortalAudience = ""
	v.Config.ExternalPortalNewTab = false
	v.Links = s.LinksFor(u, "service", v.ID)
	v.HTML = markdown(v.Config.Description)
	v.GuideHTML = markdown(v.Config.Guide)
	return &v
}
func (s *Store) AllLinks() []Link {
	rows, e := s.DB.Query("SELECT id,label,url,placement,coalesce(parent_id,0),coalesce(access_service,0),audience,position,enabled,style,new_tab,icon,description FROM links ORDER BY position,id")
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Link
	for rows.Next() {
		var v Link
		rows.Scan(&v.ID, &v.Label, &v.URL, &v.Placement, &v.ParentID, &v.AccessService, &v.Audience, &v.Position, &v.Enabled, &v.Style, &v.NewTab, &v.Icon, &v.Description)
		all = append(all, v)
	}
	return all
}
func (s *Store) parentAllowed(u *User, placement string, parent, access int) bool {
	switch placement {
	case "global":
	case "category":
		if !s.categoryAllowed(u, parent) {
			return false
		}
	case "service":
		if !s.discover(u, s.service(parent)) {
			return false
		}
	default:
		return false
	}
	if access != 0 && !s.discover(u, s.service(access)) {
		return false
	}
	return true
}
func (s *Store) linkAllowed(u *User, l Link) bool {
	return l.Enabled && l.URL != "" && s.parentAllowed(u, l.Placement, l.ParentID, l.AccessService) && s.audience(u, l.Audience, l.AccessService)
}
func (s *Store) LinksFor(u *User, placement string, parent int) []Link {
	var out []Link
	for _, l := range s.AllLinks() {
		if l.Placement == placement && l.ParentID == parent && s.linkAllowed(u, l) {
			out = append(out, l)
		}
	}
	return out
}
func (s *Store) AllAnnouncements() []Announcement {
	rows, e := s.DB.Query("SELECT id,title,body,placement,coalesce(parent_id,0),audience,coalesce(access_service,0),starts,ends,enabled FROM announcements ORDER BY id DESC")
	if e != nil {
		return nil
	}
	defer rows.Close()
	var all []Announcement
	for rows.Next() {
		var v Announcement
		rows.Scan(&v.ID, &v.Title, &v.Body, &v.Placement, &v.ParentID, &v.Audience, &v.AccessService, &v.Starts, &v.Ends, &v.Enabled)
		all = append(all, v)
	}
	return all
}
func (s *Store) announcements(u *User, placement string, parent int) []Announcement {
	var all []Announcement
	for _, v := range s.AllAnnouncements() {
		if v.Placement == placement && v.ParentID == parent && v.Enabled && (v.Starts == "" || v.Starts <= now()) && (v.Ends == "" || v.Ends > now()) && s.parentAllowed(u, v.Placement, v.ParentID, v.AccessService) && s.audience(u, v.Audience, v.AccessService) {
			v.HTML = markdown(v.Body)
			all = append(all, v)
		}
	}
	return all
}
func validURL(raw string, launch bool) error {
	if raw == "" {
		return nil
	}
	if strings.ContainsAny(raw, "\r\n\t") || strings.TrimSpace(raw) != raw {
		return errors.New("Invalid URL")
	}
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Host == "" {
		return errors.New("Use an absolute URL without embedded credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" && !(launch && u.Scheme == "steam") {
		return errors.New("Only HTTP/HTTPS links and explicitly configured steam:// launch actions are supported")
	}
	return nil
}
func markdown(raw string) template.HTML {
	var b bytes.Buffer
	goldmark.Convert([]byte(raw), &b)
	policy := bluemonday.UGCPolicy()
	policy.AllowURLSchemes("http", "https")
	policy.RequireNoFollowOnLinks(true)
	policy.RequireNoReferrerOnLinks(true)
	policy.AllowImages() // Strip all image nodes before sanitization: images belong to explicit artwork only.
	safe := bluemonday.StrictPolicy()
	_ = safe
	// Goldmark omits raw HTML by default. Remove generated image tags before the HTML allowlist.
	text := b.String()
	for {
		start := strings.Index(text, "<img ")
		if start < 0 {
			break
		}
		end := strings.Index(text[start:], ">")
		if end < 0 {
			break
		}
		text = text[:start] + text[start+end+1:]
	}
	return template.HTML(policy.Sanitize(text))
}
func nullable(id int) any {
	if id == 0 {
		return nil
	}
	return id
}

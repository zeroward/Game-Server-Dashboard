package portal

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/alexedwards/scs/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/csrf"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir, BaseURL, Addr     string
	SecretsDir                 string
	VPNEnabled                 bool
	VPNEndpoint, VPNControlDir string
	VPNDeliveryDir             string
	Production                 bool
	TrustedProxies             []string
}
type App struct {
	Store          *Store
	Sessions       *scs.SessionManager
	Templates      *template.Template
	Config         Config
	Assets         fs.FS
	csrfKey        []byte
	deliveryCipher cipher.AEAD
	secretCipher   cipher.AEAD
	WebAuthn       *webauthn.WebAuthn
}

func New(s *Store, c Config, assets fs.FS) (*App, error) {
	base, e := url.Parse(c.BaseURL)
	if e != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("BASE_URL must be the portal HTTP(S) origin without credentials, query, fragment, or subpath")
	}
	if c.Production && base.Scheme != "https" {
		return nil, errors.New("production requires HTTPS")
	}

	funcs := template.FuncMap{"seq": func(n int) []int {
		v := make([]int, n)
		for i := range v {
			v[i] = i
		}
		return v
	}, "fieldAt": func(v []Field, i int) Field {
		if i < len(v) {
			return v[i]
		}
		return Field{Type: "short"}
	}, "valueAt": func(v []Value, i int) Value {
		if i < len(v) {
			return v[i]
		}
		return Value{}
	}, "eqi": func(a, b int) bool { return a == b }, "add": func(a, b int) int { return a + b }, "date": func(s string) string {
		if len(s) >= 10 {
			return strings.ReplaceAll(s, "T", " ")
		}
		return s
	}, "contains": strings.Contains, "join": strings.Join, "audiences": func() []string { return []string{"public", "member", "access", "admin"} }, "list": func(v ...string) []string { return v }, "safeAccent": func(s string) template.CSS {
		if len(s) == 7 && s[0] == '#' {
			if _, e := hex.DecodeString(s[1:]); e == nil {
				return template.CSS(s)
			}
		}
		return "#a7c4ad"
	}}
	t, e := template.New("base").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if e != nil {
		return nil, e
	}
	a := &App{Store: s, Config: c, Templates: t, Assets: assets}
	a.Sessions = scs.New()
	a.Sessions.Store = s
	a.Sessions.Lifetime = 7 * 24 * time.Hour
	a.Sessions.IdleTimeout = 24 * time.Hour
	a.Sessions.Cookie.Name = "waypoint_session"
	a.Sessions.Cookie.HttpOnly = true
	a.Sessions.Cookie.Secure = c.Production
	a.Sessions.Cookie.SameSite = http.SameSiteLaxMode
	keyPath := filepath.Join(c.DataDir, "csrf.key")
	key, e := os.ReadFile(keyPath)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		e = os.WriteFile(keyPath, key, 0600)
	}
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, errors.New("invalid CSRF key file")
	}
	a.csrfKey = key
	if c.VPNEnabled && c.VPNDeliveryDir != "" {
		if e = a.initDelivery(); e != nil {
			return nil, e
		}
	}
	if e = a.initSecurity(); e != nil {
		return nil, e
	}
	return a, nil
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(a.Assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /{$}", a.catalog)
	mux.HandleFunc("GET /services/{slug}", a.detail)
	mux.HandleFunc("GET /services/{slug}/open", a.direct)
	mux.HandleFunc("GET /out/{id}", a.out)
	mux.HandleFunc("GET /media/{id}", a.media)
	mux.HandleFunc("GET /account/security", a.security)
	mux.HandleFunc("POST /account/security", a.security)
	mux.HandleFunc("GET /account/totp-qr", a.totpQR)
	mux.HandleFunc("GET /account/verify-email", a.verifyEmail)
	mux.HandleFunc("POST /account/verify-email", a.verifyEmail)
	mux.HandleFunc("POST /account/passkeys/{action}", a.passkey)
	mux.HandleFunc("GET /admin/email", a.emailAdmin)
	mux.HandleFunc("POST /admin/email", a.emailAdmin)
	mux.HandleFunc("POST /admin/factor-reset", a.factorReset)
	mux.HandleFunc("GET /account/{action}", a.auth)
	mux.HandleFunc("POST /account/{action}", a.auth)
	mux.HandleFunc("GET /my-access", a.myAccess)
	mux.HandleFunc("GET /my-devices", a.devices)
	mux.HandleFunc("POST /my-devices/{id}/pack", a.downloadPack)
	mux.HandleFunc("POST /my-devices", a.devices)
	mux.HandleFunc("GET /admin/vpn", a.devices)
	mux.HandleFunc("POST /admin/vpn", a.devices)
	mux.HandleFunc("GET /requests", a.requests)
	mux.HandleFunc("POST /services/{slug}/requests", a.submitRequest)
	mux.HandleFunc("GET /requests/{id}", a.requestDetail)
	mux.HandleFunc("POST /requests/{id}/{action}", a.requestAction)
	mux.HandleFunc("GET /notifications", a.notifications)
	mux.HandleFunc("POST /notifications/read", a.notifications)
	mux.HandleFunc("GET /admin", a.admin)
	mux.HandleFunc("GET /admin/{section}", a.admin)
	mux.HandleFunc("GET /admin/{section}/{id}", a.admin)
	mux.HandleFunc("POST /admin/{section}", a.adminPost)
	mux.HandleFunc("POST /admin/{section}/{id}", a.adminPost)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.fail(w, r, 404, "That page does not exist. Explore the library or return to your requests.")
	})
	protect := csrf.Protect(a.csrfKey, csrf.Secure(a.Config.Production), csrf.Path("/"), csrf.SameSite(csrf.SameSiteLaxMode), csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.fail(w, r, 403, "Your form expired or failed its security check. Reload the page and try again.")
	})))
	secured := a.Sessions.LoadAndSave(protect(mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: http:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Vary", "Cookie")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 9<<20)
		if !a.Config.Production {
			r = csrf.PlaintextHTTPRequest(r)
		}
		secured.ServeHTTP(w, r)
	})
}
func (a *App) page(r *http.Request, title, view string) *Page {
	u := a.current(r)
	p := &Page{Title: title, View: view, User: u, CSRF: csrf.TemplateField(r), Settings: a.Store.Settings(), Success: r.URL.Query().Get("success")}
	p.VPNEnabled = a.Config.VPNEnabled
	p.GlobalLinks = a.Store.LinksFor(u, "global", 0)
	if u != nil {
		p.Unread = len(a.visibleNotifications(u, true))
	}
	return p
}
func (a *App) render(w http.ResponseWriter, r *http.Request, p *Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e := a.Templates.ExecuteTemplate(w, "base", p); e != nil {
		log.Printf("template error: %v", e)
	}
}
func (a *App) fail(w http.ResponseWriter, r *http.Request, code int, message string) {
	p := a.page(r, http.StatusText(code), "error")
	p.Error = message
	w.WriteHeader(code)
	a.render(w, r, p)
}
func (a *App) member(w http.ResponseWriter, r *http.Request) *User {
	u := a.current(r)
	if u == nil {
		if r.Method == "GET" {
			http.Redirect(w, r, "/account/login", 303)
		} else {
			a.fail(w, r, 403, "Sign in to continue.")
		}
	}
	return u
}
func (a *App) administrator(w http.ResponseWriter, r *http.Request) *User {
	u := a.member(w, r)
	if u != nil && u.Role != "admin" {
		a.fail(w, r, 403, "This page is for administrators.")
		return nil
	}
	return u
}
func number(s string) int { n, _ := strconv.Atoi(s); return n }
func (a *App) clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	trusted := false
	ip := net.ParseIP(host)
	for _, s := range a.Config.TrustedProxies {
		_, n, e := net.ParseCIDR(s)
		if e == nil && n.Contains(ip) {
			trusted = true
		}
	}
	if trusted {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			cip := net.ParseIP(candidate)
			if cip == nil {
				continue
			}
			inside := false
			for _, s := range a.Config.TrustedProxies {
				_, n, e := net.ParseCIDR(s)
				if e == nil && n.Contains(cip) {
					inside = true
				}
			}
			if !inside {
				return candidate
			}
		}
	}
	return host
}
func (a *App) findService(slug string) *Service {
	for _, v := range a.Store.AllServices() {
		if v.Slug == slug {
			return &v
		}
	}
	return nil
}
func (a *App) catalog(w http.ResponseWriter, r *http.Request) {
	p := a.page(r, "Your library", "catalog")
	if p.User == nil && !p.Settings.Public {
		http.Redirect(w, r, "/account/login", 303)
		return
	}
	p.Query = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	p.Filter = r.URL.Query().Get("category")
	p.Tag = r.URL.Query().Get("tag")
	for _, c := range a.Store.Categories() {
		if a.Store.categoryAllowed(p.User, c.ID) {
			p.Categories = append(p.Categories, c)
		}
	}
	for _, raw := range a.Store.AllServices() {
		v := a.Store.permitted(p.User, raw)
		if v == nil {
			continue
		}
		if p.User != nil && p.User.Role == "admin" && (!v.Published || v.Archived) {
			continue
		}
		hay := strings.ToLower(v.Name + " " + v.Config.Game + " " + v.Config.Summary + " " + v.Config.Description + " " + v.Config.Tags)
		if p.Query != "" && !strings.Contains(hay, p.Query) {
			continue
		}
		if p.Filter != "" && number(p.Filter) != v.CategoryID {
			continue
		}
		if p.Tag != "" && !strings.Contains(strings.ToLower(v.Config.Tags), strings.ToLower(p.Tag)) {
			continue
		}
		p.Services = append(p.Services, *v)
	}
	p.Announcements = a.Store.announcements(p.User, "global", 0)
	if p.Filter != "" && a.Store.categoryAllowed(p.User, number(p.Filter)) {
		p.Links = a.Store.LinksFor(p.User, "category", number(p.Filter))
		p.Announcements = append(p.Announcements, a.Store.announcements(p.User, "category", number(p.Filter))...)
	}
	a.render(w, r, p)
}
func (a *App) detail(w http.ResponseWriter, r *http.Request) {
	p := a.page(r, "Service", "service")
	v := a.findService(r.PathValue("slug"))
	if v == nil || !a.Store.discover(p.User, v) {
		a.fail(w, r, 404, "This service is unavailable.")
		return
	}
	p.Service = a.Store.permitted(p.User, *v)
	p.Title = v.Name
	p.Announcements = a.Store.announcements(p.User, "service", v.ID)
	p.Links = a.Store.LinksFor(p.User, "category", v.CategoryID)
	if p.User != nil {
		for _, req := range a.Store.Requests(p.User) {
			if req.ServiceID == v.ID {
				p.Requests = append(p.Requests, req)
			}
		}
	}
	a.render(w, r, p)
}
func (a *App) direct(w http.ResponseWriter, r *http.Request) {
	u := a.current(r)
	v := a.findService(r.PathValue("slug"))
	if v == nil || !a.Store.discover(u, v) {
		a.fail(w, r, 404, "This service is unavailable.")
		return
	}
	for _, l := range a.Store.LinksFor(u, "service", v.ID) {
		if l.ID == v.Config.DirectLink {
			http.Redirect(w, r, l.URL, 302)
			return
		}
	}
	http.Redirect(w, r, "/services/"+v.Slug, 302)
}
func (a *App) out(w http.ResponseWriter, r *http.Request) {
	for _, l := range a.Store.AllLinks() {
		if l.ID == number(r.PathValue("id")) && a.Store.linkAllowed(a.current(r), l) {
			http.Redirect(w, r, l.URL, 302)
			return
		}
	}
	a.fail(w, r, 404, "This destination is unavailable.")
}

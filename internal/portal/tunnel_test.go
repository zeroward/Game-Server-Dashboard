package portal

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// A TLS reverse proxy forwarding to an HTTP origin matches the tunnel boundary.
// No external tunnel or Cloudflare credentials are needed for this regression test.
func TestTunnelHTTPSProxyLoginAndOrigin(t *testing.T) {
	a, _, _, _ := fixture(t)
	a.Config.Production = true
	a.Sessions.Cookie.Secure = true
	origin := httptest.NewServer(a.Handler())
	defer origin.Close()
	target, _ := url.Parse(origin.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	edge := httptest.NewTLSServer(proxy)
	defer edge.Close()
	client := edge.Client()
	client.Jar, _ = cookiejar.New(nil)
	body, status := post(t, client, edge.URL, "/account/login", url.Values{"username": {"alice"}, "password": {"a long test password"}})
	enrollTestClient(t, client, edge.URL)
	body, status = get(t, client, edge.URL+"/")
	if status != 200 || !strings.Contains(body, "Make yourself at home") {
		t.Fatal("HTTPS to HTTP proxy login failed", status)
	}
	body, _ = get(t, client, edge.URL+"/account/password")
	token := csrfRE.FindStringSubmatch(body)
	if len(token) != 2 {
		t.Fatal("missing authenticated form")
	}
	req, _ := http.NewRequest("POST", edge.URL+"/account/logout", strings.NewReader(url.Values{"gorilla.csrf.Token": {token[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://untrusted.invalid")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("cross-origin mutation accepted behind proxy")
	}
	body, status = post(t, client, edge.URL, "/account/logout", url.Values{})
	if status != 200 || !strings.Contains(body, "Welcome back.") {
		t.Fatal("proxy logout failed", status)
	}
	fresh := &http.Client{Transport: edge.Client().Transport}
	res, e = fresh.Get(edge.URL + "/account/login")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	found := false
	for _, cookie := range res.Cookies() {
		if cookie.Name == "_gorilla_csrf" {
			found = true
			if !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("proxy weakened cookies")
			}
		}
	}
	if !found || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("proxy cache/cookie protection missing")
	}
}

func TestTunnelExactProxyTrust(t *testing.T) {
	a := &App{Config: Config{TrustedProxies: []string{"172.30.250.2/32"}}}
	for _, tc := range []struct{ remote, forwarded, want string }{
		{"172.30.250.2:50000", "192.0.2.123, 198.51.100.7", "198.51.100.7"},
		{"172.30.250.3:50000", "192.0.2.123, 198.51.100.7", "172.30.250.3"},
		{"203.0.113.20:50000", "192.0.2.123", "203.0.113.20"},
		{"172.30.250.2:50000", "", "172.30.250.2"},
	} {
		req := httptest.NewRequest("GET", "http://portal:8080/", nil)
		req.RemoteAddr = tc.remote
		req.Header.Set("X-Forwarded-For", tc.forwarded)
		req.Header.Set("CF-Connecting-IP", "192.0.2.222")
		if got := a.clientIP(req); got != tc.want {
			t.Fatalf("wrong client IP: got %s want %s", got, tc.want)
		}
	}
}

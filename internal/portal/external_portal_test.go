package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExternalPortalEditorAndValidation(t *testing.T) {
	a, admin, alice, _ := fixture(t)
	values := url.Values{"name": {"External game"}, "slug": {"external-game"}, "type": {"game"}, "audience": {"member"}, "details_audience": {"access"}, "mode": {"external"}, "published": {"on"}, "focal_x": {"50"}, "focal_y": {"50"}, "external_portal_url": {"https://signup.example.invalid/create"}, "external_portal_label": {"Create game account"}, "external_portal_audience": {"member"}, "external_portal_new_tab": {"on"}}
	id, e := a.saveService(admin, 0, formRequest(values))
	if e != nil {
		t.Fatal(e)
	}
	v := a.Store.service(id)
	if v.Config.ExternalPortalURL != values.Get("external_portal_url") {
		t.Fatal("destination did not persist")
	}
	permitted := a.Store.permitted(alice, *v)
	if permitted.Details || permitted.Requestable || permitted.ExternalPortal == nil || !permitted.ExternalPortal.NewTab {
		t.Fatal("signup should not require connection-detail access or create a duplicate request")
	}
	if permitted.Config.ExternalPortalURL != "" {
		t.Fatal("raw configuration retained")
	}
	for _, bad := range []string{"javascript:alert(1)", "https://user:password@example.invalid", "steam://run/123", "https://host.invalid\r\nLocation: other"} {
		values.Set("external_portal_url", bad)
		if _, e = a.saveService(admin, id, formRequest(values)); e == nil {
			t.Fatal("unsafe signup URL accepted")
		}
	}
	values.Set("external_portal_url", "http://accounts.internal:8080/register")
	if _, e = a.saveService(admin, id, formRequest(values)); e != nil {
		t.Fatal("explicit internal HTTP destination rejected", e)
	}
	values.Set("external_portal_url", "")
	if _, e = a.saveService(admin, id, formRequest(values)); e != nil {
		t.Fatal(e)
	}
	if a.Store.permitted(alice, *a.Store.service(id)).ExternalPortal != nil {
		t.Fatal("cleared URL still active")
	}
}
func TestExternalSignupAudienceRedirectAndPayloadPrivacy(t *testing.T) {
	a, _, alice, _ := fixture(t)
	v := serviceNamed(t, a.Store, "world-of-warcraft")
	v.Config.ExternalPortalURL = "https://PRIVATE_SIGNUP.invalid/register"
	v.Config.ExternalPortalLabel = "PRIVATE_SIGNUP_LABEL"
	v.Config.ExternalPortalAudience = "admin"
	setConfig(t, a.Store, v)
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	client := loginClient(t, server, "alice")
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	checkDenied := func() {
		t.Helper()
		res, e := client.Get(server.URL + "/services/" + v.Slug + "/signup")
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 404 || res.Header.Get("Location") != "" {
			t.Fatal("restricted signup redirect exposed")
		}
	}
	checkDenied()
	body, _ := get(t, client, server.URL+"/services/"+v.Slug)
	assertNo(t, body, "PRIVATE_SIGNUP")
	b, _ := json.Marshal(a.Store.permitted(alice, *a.Store.service(v.ID)))
	assertNo(t, string(b), "PRIVATE_SIGNUP")
	v.Config.ExternalPortalAudience = "member"
	setConfig(t, a.Store, v)
	res, e := client.Get(server.URL + "/services/" + v.Slug + "/signup")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 302 || res.Header.Get("Location") != v.Config.ExternalPortalURL || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("permitted signup unavailable or cacheable")
	}
	v.Config.ExternalPortalAudience = "access"
	setConfig(t, a.Store, v)
	checkDenied()
	v.Config.ExternalPortalAudience = "public"
	setConfig(t, a.Store, v)
	a.Store.DB.Exec("UPDATE services SET published=0 WHERE id=?", v.ID)
	checkDenied()
	a.Store.DB.Exec("UPDATE services SET published=1 WHERE id=?", v.ID)
	a.Store.DB.Exec("UPDATE categories SET audience='admin' WHERE id=?", v.CategoryID)
	checkDenied()
	a.Store.DB.Exec("UPDATE categories SET audience='member' WHERE id=?", v.CategoryID)
	a.Store.DB.Exec("UPDATE services SET mode='info' WHERE id=?", v.ID)
	checkDenied()
}

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/admin"
	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
)

const adminSecret = "tavadm_server-test"

func adminServer(t *testing.T, withTokens bool, adm *admin.Deps) (*httptest.Server, *Metrics) {
	t.Helper()
	holder := &config.Holder{}
	snap := &config.Snapshot{Revision: "rev-1", AdminTokens: map[string]*config.AdminToken{}}
	if withTokens {
		snap.AdminTokens[auth.HashKey(adminSecret)] = &config.AdminToken{ID: "ops", Role: config.RoleAdmin}
	}
	holder.Store(snap)
	m := NewMetrics()
	srv := httptest.NewServer(NewAdminHandler(holder, m, nil, adm))
	t.Cleanup(srv.Close)
	return srv, m
}

func status(t *testing.T, method, url, token string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r.StatusCode
}

func TestAdminAPIIsAbsentUnlessAsked(t *testing.T) {
	srv, _ := adminServer(t, true, nil)
	for _, p := range []string{"/admin/v1/whoami", "/admin/docs", "/admin/v1/openapi.yaml"} {
		if got := status(t, "GET", srv.URL+p, adminSecret); got != http.StatusNotFound {
			t.Errorf("%s = %d without admin deps, want 404", p, got)
		}
	}
	if got := status(t, "GET", srv.URL+"/healthz", ""); got != http.StatusOK {
		t.Errorf("healthz = %d", got)
	}
}

func TestAdminAPIAndItsReferenceNeedTokens(t *testing.T) {
	srv, _ := adminServer(t, false, &admin.Deps{Log: discard()})
	for _, p := range []string{"/admin/v1/whoami", "/admin/docs", "/admin/docs/scalar.js", "/admin/v1/openapi.yaml"} {
		if got := status(t, "GET", srv.URL+p, adminSecret); got != http.StatusNotFound {
			t.Errorf("%s = %d without any admin token, want 404", p, got)
		}
	}
}

func TestAdminHealthEndpointsStayOpen(t *testing.T) {
	srv, _ := adminServer(t, true, &admin.Deps{Log: discard()})
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if got := status(t, "GET", srv.URL+p, ""); got != http.StatusOK {
			t.Errorf("%s = %d without a credential, want 200", p, got)
		}
	}
}

// Every operation of the administration API's description must be routed and
// protected: this catches the description drifting from the handlers.
func TestAdminOpenAPIOperationsAreRoutedAndProtected(t *testing.T) {
	srv, _ := adminServer(t, true, &admin.Deps{Log: discard()})
	r, err := http.Get(srv.URL + "/admin/v1/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/admin/v1/openapi.yaml = %d", r.StatusCode)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.NewDecoder(r.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for path, ops := range doc.Paths {
		for method := range ops {
			if got := status(t, strings.ToUpper(method), srv.URL+path, ""); got != http.StatusUnauthorized {
				t.Errorf("%s %s answered %d without a token, want 401: is it routed?", method, path, got)
			}
			checked++
		}
	}
	if checked < 4 {
		t.Errorf("only %d operations checked", checked)
	}
}

func TestAdminReferenceIsSelfContained(t *testing.T) {
	srv, _ := adminServer(t, true, &admin.Deps{Log: discard()})
	r, err := http.Get(srv.URL + "/admin/docs")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	page := string(body)
	if r.StatusCode != http.StatusOK || !strings.Contains(page, `data-url="/admin/v1/openapi.yaml"`) || !strings.Contains(page, `src="/admin/docs/scalar.js"`) {
		t.Fatalf("page: %d %s", r.StatusCode, page)
	}
	if regexp.MustCompile(`https?://`).MatchString(page) {
		t.Errorf("the page references an external resource: %s", page)
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || regexp.MustCompile(`https?:`).MatchString(csp) {
		t.Errorf("CSP = %q", csp)
	}
	if got := status(t, "GET", srv.URL+"/admin/docs/scalar.js", ""); got != http.StatusOK {
		t.Errorf("viewer = %d", got)
	}
}

func TestAdminCallsAreCountedWithoutNamingWho(t *testing.T) {
	srv, m := adminServer(t, true, &admin.Deps{Log: discard()})
	status(t, "GET", srv.URL+"/admin/v1/whoami", adminSecret)
	status(t, "GET", srv.URL+"/admin/v1/whoami", "tavadm_wrong")
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	// whoami is a read: only the refusal is an outcome worth a counter
	if !strings.Contains(out, `tavian_admin_requests_total{action="whoami",outcome="unauthenticated"} 1`) {
		t.Errorf("metrics lack the refused call:\n%s", grepLines(out, "tavian_admin"))
	}
	if strings.Contains(out, adminSecret) || strings.Contains(out, "tavadm_wrong") || strings.Contains(out, `actor=`) {
		t.Error("metrics name a credential or an actor")
	}
}

func TestAnAdminTokenIsNotADataPlaneKey(t *testing.T) {
	f := newFixture(t, 1<<20)
	if got := status(t, "GET", f.gw.URL+"/v1/models", adminSecret); got != http.StatusUnauthorized {
		t.Errorf("an admin token was accepted by the data plane: %d", got)
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestAdminTokenExpiryMetrics(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{AdminTokens: map[string]*config.AdminToken{
		"h1": {ID: "gone", ExpiresAt: now.Add(-time.Hour)},
		"h2": {ID: "soon", ExpiresAt: now.Add(48 * time.Hour)},
		"h3": {ID: "none"},
	}})
	m := NewMetrics()
	m.WatchAdminTokens(holder, func() time.Time { return now })
	scrape := func() string {
		rec := httptest.NewRecorder()
		m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		return grepLines(rec.Body.String(), "tavian_admin_tokens") + "\n"
	}
	out := scrape()
	if !strings.Contains(out, "tavian_admin_tokens_expired 1\n") || !strings.Contains(out, "tavian_admin_tokens_next_expiry_seconds 172800\n") {
		t.Errorf("metrics:\n%s", out)
	}
	if strings.Contains(out, "gone") || strings.Contains(out, "soon") {
		t.Errorf("a token id is in the metrics:\n%s", out)
	}
	// no tokens, no metrics: a gateway without the API has nothing to alert on
	holder.Store(&config.Snapshot{})
	if out := scrape(); strings.Contains(out, "\ntavian_admin_tokens_expired ") || strings.HasPrefix(out, "tavian_admin_tokens_expired ") {
		t.Errorf("metrics without tokens:\n%s", out)
	}
}

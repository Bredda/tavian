package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/store"
)

type fakeStore struct {
	mu      sync.Mutex
	changes []store.AdminChange
	failOn  bool
}

func (f *fakeStore) RecordAdminChange(_ context.Context, c store.AdminChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn {
		return errors.New("database down")
	}
	f.changes = append(f.changes, c)
	return nil
}

func (f *fakeStore) ListAdminChanges(_ context.Context, limit int, before int64) ([]store.AdminChange, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn {
		return nil, 0, errors.New("database down")
	}
	var out []store.AdminChange
	for i := len(f.changes) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, f.changes[i])
	}
	if len(out) < len(f.changes) { // more to read: the cursor of a real store
		return out, int64(len(f.changes) - len(out)), nil
	}
	return out, 0, nil
}

const (
	secret  = "tavadm_test-secret"
	secret2 = "tavadm_other-secret"
)

type fixture struct {
	srv      *httptest.Server
	store    *fakeStore
	holder   *config.Holder
	observed []string
	reloads  int
}

// newFixture serves the API with two tokens (alice and bob). reload decides
// what the reloader does after it has called record.
func newFixture(t *testing.T, reload func(record Record) (Reloaded, error)) *fixture {
	t.Helper()
	f := &fixture{store: &fakeStore{}, holder: &config.Holder{}}
	f.holder.Store(&config.Snapshot{
		Revision: "rev-1", Profile: "standard",
		AdminTokens: map[string]*config.AdminToken{
			auth.HashKey(secret):  {ID: "alice"},
			auth.HashKey(secret2): {ID: "bob"},
		},
	})
	d := Deps{
		Snap: f.holder, Store: f.store, Log: slog.New(slog.DiscardHandler),
		Observe: func(action, outcome string) { f.observed = append(f.observed, action+":"+outcome) },
		Now:     func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) },
	}
	if reload != nil {
		d.Reload = func(_ context.Context, record Record) (Reloaded, error) {
			f.reloads++
			return reload(record)
		}
	}
	mux := http.NewServeMux()
	Register(mux, d)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) do(t *testing.T, method, path, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func errCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	return e.Error.Code
}

func TestEveryRouteNeedsAnAdminToken(t *testing.T) {
	f := newFixture(t, func(Record) (Reloaded, error) { t.Error("reload ran without authentication"); return Reloaded{}, nil })
	for _, r := range []struct{ method, path string }{
		{"GET", "/admin/v1/whoami"}, {"GET", "/admin/v1/config"}, {"GET", "/admin/v1/changes"}, {"POST", "/admin/v1/config/reload"},
	} {
		for name, token := range map[string]string{"none": "", "unknown": "tavadm_nope", "an API key": "tav_" + strings.Repeat("a", 43)} {
			res, body := f.do(t, r.method, r.path, token)
			if res.StatusCode != http.StatusUnauthorized || errCode(t, body) != "unauthenticated" || res.Header.Get("WWW-Authenticate") != `Bearer realm="tavian-admin"` {
				t.Errorf("%s %s with %s: %d %s", r.method, r.path, name, res.StatusCode, body)
			}
		}
	}
	if len(f.store.changes) != 0 {
		t.Errorf("a refused call left a change record: %+v", f.store.changes)
	}
}

func TestDataPlaneCredentialsAreNotAdminTokens(t *testing.T) {
	f := newFixture(t, nil)
	s := f.holder.Load()
	key := "tav_" + strings.Repeat("k", 43)
	s.Keys = map[string]*config.APIKey{auth.HashKey(key): {ID: "app", AllowedModels: []string{"*"}}}
	if res, _ := f.do(t, "GET", "/admin/v1/whoami", key); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an API key opened the admin API: %d", res.StatusCode)
	}
	// and the other way round: the data plane's authenticator does not know admin tokens
	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	if _, err := (auth.APIKeyAuthenticator{Snap: f.holder}).Authenticate(r); err == nil {
		t.Error("an admin token authenticated on the data plane")
	}
}

func TestNotServedWithoutTokens(t *testing.T) {
	f := newFixture(t, nil)
	f.holder.Store(&config.Snapshot{Revision: "rev-1", AdminTokens: map[string]*config.AdminToken{}})
	for _, p := range []string{"/admin/v1/whoami", "/admin/v1/config", "/admin/v1/changes"} {
		if res, _ := f.do(t, "GET", p, secret); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 while no token is configured", p, res.StatusCode)
		}
	}
	if Enabled(&config.Holder{}) {
		t.Error("enabled without a snapshot")
	}
}

func TestWhoamiAndConfigShow(t *testing.T) {
	f := newFixture(t, nil)
	res, body := f.do(t, "GET", "/admin/v1/whoami", secret2)
	if res.StatusCode != 200 || !strings.Contains(body, `"actor":"bob"`) {
		t.Errorf("whoami: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("X-Request-Id") == "" || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", res.Header)
	}
	res, body = f.do(t, "GET", "/admin/v1/config", secret)
	if res.StatusCode != 200 || !strings.Contains(body, `"revision":"rev-1"`) || !strings.Contains(body, `"admin_tokens":2`) {
		t.Errorf("config: %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, secret) || strings.Contains(body, auth.HashKey(secret)) {
		t.Errorf("config summary leaks a credential: %s", body)
	}
}

func TestReloadIsRecordedBeforeItIsApplied(t *testing.T) {
	var recordedBeforeApply bool
	var f *fixture
	f = newFixture(t, func(record Record) (Reloaded, error) {
		if err := record("rev-2", map[string]any{"previous": "rev-1"}); err != nil {
			return Reloaded{}, err
		}
		recordedBeforeApply = len(f.store.changes) == 1
		return Reloaded{Revision: "rev-2", Previous: "rev-1"}, nil
	})
	req, _ := http.NewRequest("POST", f.srv.URL+"/admin/v1/config/reload", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Request-Id", "req-12345678")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"revision":"rev-2"`) {
		t.Fatalf("reload: %d %s", res.StatusCode, b)
	}
	if !recordedBeforeApply {
		t.Error("the change was not recorded when the reloader went on to apply it")
	}
	if len(f.store.changes) != 1 {
		t.Fatalf("changes = %+v", f.store.changes)
	}
	c := f.store.changes[0]
	if c.Actor != "alice" || c.Action != ActionReload || c.Target != "rev-2" || c.Outcome != store.OutcomeApplied ||
		c.RequestID != "req-12345678" || c.RemoteAddr != "127.0.0.1" || c.EventID == "" ||
		!c.OccurredAt.Equal(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)) || !strings.Contains(string(c.Detail), "rev-1") {
		t.Errorf("record = %+v", c)
	}
	if strings.Join(f.observed, ",") != "config.reload:applied" {
		t.Errorf("observed = %v", f.observed)
	}
}

func TestReloadRefusedWhenItCannotBeRecorded(t *testing.T) {
	applied := false
	f := newFixture(t, func(record Record) (Reloaded, error) {
		if err := record("rev-2", nil); err != nil {
			return Reloaded{}, err
		}
		applied = true
		return Reloaded{Revision: "rev-2"}, nil
	})
	f.store.failOn = true
	res, body := f.do(t, "POST", "/admin/v1/config/reload", secret)
	if res.StatusCode != http.StatusServiceUnavailable || errCode(t, body) != "audit_unavailable" {
		t.Errorf("reload: %d %s", res.StatusCode, body)
	}
	if applied {
		t.Error("the change was applied although it could not be recorded")
	}
	if strings.Join(f.observed, ",") != "config.reload:audit_unavailable" {
		t.Errorf("observed = %v", f.observed)
	}
}

func TestRejectedReloadIsRecordedAndNothingChanges(t *testing.T) {
	f := newFixture(t, func(Record) (Reloaded, error) {
		return Reloaded{}, &Rejection{Code: "invalid_configuration", Message: "models[0]: bad"}
	})
	res, body := f.do(t, "POST", "/admin/v1/config/reload", secret)
	if res.StatusCode != http.StatusUnprocessableEntity || errCode(t, body) != "invalid_configuration" || !strings.Contains(body, "models[0]: bad") {
		t.Errorf("reload: %d %s", res.StatusCode, body)
	}
	if len(f.store.changes) != 1 || f.store.changes[0].Outcome != store.OutcomeRejected || f.store.changes[0].Actor != "alice" ||
		!strings.Contains(string(f.store.changes[0].Detail), "invalid_configuration") {
		t.Errorf("changes = %+v", f.store.changes)
	}

	// a refusal still stands when the record of it cannot be written
	f.store.failOn = true
	if res, body = f.do(t, "POST", "/admin/v1/config/reload", secret); res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("reload with the store down: %d %s", res.StatusCode, body)
	}

	// a custom status is kept
	f2 := newFixture(t, func(Record) (Reloaded, error) {
		return Reloaded{}, &Rejection{Code: "restart_required", Message: "x", Status: http.StatusConflict}
	})
	if res, _ = f2.do(t, "POST", "/admin/v1/config/reload", secret); res.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", res.StatusCode)
	}
}

func TestReloadFailureOfTheGatewayIsNotARejection(t *testing.T) {
	f := newFixture(t, func(Record) (Reloaded, error) { return Reloaded{}, errors.New("database: connection refused") })
	res, body := f.do(t, "POST", "/admin/v1/config/reload", secret)
	if res.StatusCode != http.StatusServiceUnavailable || errCode(t, body) != "unavailable" || strings.Contains(body, "connection refused") {
		t.Errorf("reload: %d %s", res.StatusCode, body)
	}
	if len(f.store.changes) != 0 {
		t.Errorf("a failure that changed nothing was recorded as a change: %+v", f.store.changes)
	}
}

func TestChangesListsWhatHappened(t *testing.T) {
	f := newFixture(t, func(record Record) (Reloaded, error) {
		return Reloaded{Revision: "r"}, record("r", nil)
	})
	f.do(t, "POST", "/admin/v1/config/reload", secret)
	f.do(t, "POST", "/admin/v1/config/reload", secret2)
	res, body := f.do(t, "GET", "/admin/v1/changes?limit=10", secret)
	var out struct {
		Changes []store.AdminChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || res.StatusCode != 200 || len(out.Changes) != 2 || out.Changes[0].Actor != "bob" {
		t.Fatalf("changes: %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, `"next"`) {
		t.Errorf("the last page offers a next page: %s", body)
	}
	if _, body := f.do(t, "GET", "/admin/v1/changes?limit=1", secret); !strings.Contains(body, `"next":"1"`) {
		t.Errorf("a page that is not the last has no next: %s", body)
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=x", "before=0", "before=x"} {
		if res, _ := f.do(t, "GET", "/admin/v1/changes?"+q, secret); res.StatusCode != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, res.StatusCode)
		}
	}
	f.store.failOn = true
	if res, body := f.do(t, "GET", "/admin/v1/changes", secret); res.StatusCode != http.StatusServiceUnavailable || strings.Contains(body, "database down") {
		t.Errorf("store down: %d %s", res.StatusCode, body)
	}
}

func TestEmptyHistoryIsAnEmptyList(t *testing.T) {
	f := newFixture(t, nil)
	if _, body := f.do(t, "GET", "/admin/v1/changes", secret); !strings.Contains(body, `"changes":[]`) {
		t.Errorf("body = %s", body)
	}
}

func TestReloadWithoutReloader(t *testing.T) {
	f := newFixture(t, nil)
	if res, _ := f.do(t, "POST", "/admin/v1/config/reload", secret); res.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d", res.StatusCode)
	}
}

func TestAuthenticationFailureIsLoggedWithoutTheCredential(t *testing.T) {
	var logs strings.Builder
	f := newFixture(t, nil)
	h := slog.NewTextHandler(&logs, nil)
	mux := http.NewServeMux()
	Register(mux, Deps{Snap: f.holder, Store: f.store, Log: slog.New(h)})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/admin/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer tavadm_guess-me-please")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.Contains(logs.String(), "admin authentication failed") || strings.Contains(logs.String(), "guess-me-please") {
		t.Errorf("log = %s", logs.String())
	}
}

package admin

import (
	"bytes"
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
	"github.com/bredda/tavian/internal/textdiff"
)

type fakeStore struct {
	mu        sync.Mutex
	changes   []store.AdminChange
	revisions []store.StoredRevision // oldest first
	active    string
	failOn    bool
}

var errDown = errors.New("database down")

func (f *fakeStore) RecordAdminChange(_ context.Context, c store.AdminChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn {
		return errDown
	}
	f.changes = append(f.changes, c)
	return nil
}

func (f *fakeStore) ListAdminChanges(_ context.Context, limit int, _ int64) ([]store.AdminChange, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn {
		return nil, 0, errDown
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

func (f *fakeStore) GetRevision(_ context.Context, id string) (store.StoredRevision, error) {
	if f.failOn {
		return store.StoredRevision{}, errDown
	}
	for _, r := range f.revisions {
		if r.ID == id {
			return r, nil
		}
	}
	return store.StoredRevision{}, store.ErrNotFound
}

func (f *fakeStore) ListRevisions(_ context.Context, limit int, _ int64) ([]store.StoredRevision, int64, error) {
	if f.failOn {
		return nil, 0, errDown
	}
	var out []store.StoredRevision
	for i := len(f.revisions) - 1; i >= 0 && len(out) < limit; i-- {
		r := f.revisions[i]
		r.YAML, r.Policies = nil, nil
		out = append(out, r)
	}
	if len(out) < len(f.revisions) {
		return out, out[len(out)-1].Seq, nil
	}
	return out, 0, nil
}

func (f *fakeStore) ActiveRevision(context.Context) (store.Active, bool, error) {
	if f.failOn {
		return store.Active{}, false, errDown
	}
	return store.Active{Revision: f.active}, f.active != "", nil
}

// fakeControl lets a test decide what each operation does and sees what it was asked.
type fakeControl struct {
	reload   func(Actor) (Result, error)
	apply    func(Actor, ApplyRequest) (Result, error)
	rollback func(Actor, RollbackRequest) (Result, error)
	validate func(ApplyRequest) Validation

	who      Actor
	gotApply ApplyRequest
	gotRoll  RollbackRequest
	calls    int
}

func (c *fakeControl) Reload(_ context.Context, who Actor) (Result, error) {
	c.calls++
	c.who = who
	return c.reload(who)
}

func (c *fakeControl) Apply(_ context.Context, who Actor, r ApplyRequest) (Result, error) {
	c.calls++
	c.who, c.gotApply = who, r
	return c.apply(who, r)
}

func (c *fakeControl) Rollback(_ context.Context, who Actor, r RollbackRequest) (Result, error) {
	c.calls++
	c.who, c.gotRoll = who, r
	return c.rollback(who, r)
}

func (c *fakeControl) Validate(_ context.Context, r ApplyRequest) Validation {
	c.gotApply = r
	return c.validate(r)
}

const (
	secret  = "tavadm_test-secret"
	secret2 = "tavadm_other-secret"
)

type fixture struct {
	srv      *httptest.Server
	store    *fakeStore
	control  *fakeControl
	holder   *config.Holder
	observed []string
}

func ok(rev string) func(Actor) (Result, error) {
	return func(Actor) (Result, error) { return Result{Revision: rev, Previous: "000000000000"}, nil }
}

// newFixture serves the API with two tokens (alice and bob) and a controller
// that does nothing unless a test says so.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: &fakeStore{}, holder: &config.Holder{}, control: &fakeControl{}}
	f.holder.Store(&config.Snapshot{
		Revision: "aaaaaaaaaaaa", Profile: "standard",
		AdminTokens: map[string]*config.AdminToken{
			auth.HashKey(secret):  {ID: "alice"},
			auth.HashKey(secret2): {ID: "bob"},
		},
	})
	f.control.reload = ok("bbbbbbbbbbbb")
	f.control.apply = func(Actor, ApplyRequest) (Result, error) { return Result{Revision: "bbbbbbbbbbbb"}, nil }
	f.control.rollback = func(Actor, RollbackRequest) (Result, error) { return Result{Revision: "bbbbbbbbbbbb"}, nil }
	f.control.validate = func(ApplyRequest) Validation { return Validation{Valid: true, Applicable: true} }
	f.srv = f.serve(t, f.control)
	return f
}

func (f *fixture) serve(t *testing.T, c Controller) *httptest.Server {
	t.Helper()
	d := Deps{
		Snap: f.holder, Store: f.store, Log: slog.New(slog.DiscardHandler),
		Observe: func(action, outcome string) { f.observed = append(f.observed, action+":"+outcome) },
		Now:     func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) },
	}
	if c != nil {
		d.Control = c
	}
	mux := http.NewServeMux()
	Register(mux, d)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fixture) do(t *testing.T, method, path, token, body string) (*http.Response, string) {
	t.Helper()
	return f.doTo(t, f.srv, method, path, token, body, nil)
}

func (f *fixture) doTo(t *testing.T, srv *httptest.Server, method, path, token, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
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

var allRoutes = []struct{ method, path string }{
	{"GET", "/admin/v1/whoami"}, {"GET", "/admin/v1/config"}, {"GET", "/admin/v1/changes"},
	{"GET", "/admin/v1/config/revisions"}, {"GET", "/admin/v1/config/revisions/active"},
	{"GET", "/admin/v1/config/diff?from=active"},
	{"POST", "/admin/v1/config/validate"}, {"POST", "/admin/v1/config/reload"},
	{"POST", "/admin/v1/config/apply"}, {"POST", "/admin/v1/config/rollback"},
}

func TestEveryRouteNeedsAnAdminToken(t *testing.T) {
	f := newFixture(t)
	for _, r := range allRoutes {
		for name, token := range map[string]string{"none": "", "unknown": "tavadm_nope", "an API key": "tav_" + strings.Repeat("a", 43)} {
			res, body := f.do(t, r.method, r.path, token, `{"base":"aaaaaaaaaaaa","revision":"aaaaaaaaaaaa","config":"x"}`)
			if res.StatusCode != http.StatusUnauthorized || errCode(t, body) != "unauthenticated" || res.Header.Get("WWW-Authenticate") != `Bearer realm="tavian-admin"` {
				t.Errorf("%s %s with %s: %d %s", r.method, r.path, name, res.StatusCode, body)
			}
		}
	}
	if f.control.calls != 0 || len(f.store.changes) != 0 {
		t.Errorf("a refused call reached the controller (%d) or left a record (%+v)", f.control.calls, f.store.changes)
	}
}

func TestDataPlaneCredentialsAreNotAdminTokens(t *testing.T) {
	f := newFixture(t)
	s := f.holder.Load()
	key := "tav_" + strings.Repeat("k", 43)
	s.Keys = map[string]*config.APIKey{auth.HashKey(key): {ID: "app", AllowedModels: []string{"*"}}}
	if res, _ := f.do(t, "GET", "/admin/v1/whoami", key, ""); res.StatusCode != http.StatusUnauthorized {
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
	f := newFixture(t)
	f.holder.Store(&config.Snapshot{Revision: "aaaaaaaaaaaa", AdminTokens: map[string]*config.AdminToken{}})
	for _, r := range allRoutes {
		if res, _ := f.do(t, r.method, r.path, secret, `{}`); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 while no token is configured", r.method, r.path, res.StatusCode)
		}
	}
	if Enabled(&config.Holder{}) {
		t.Error("enabled without a snapshot")
	}
}

func TestWhoamiAndConfigShow(t *testing.T) {
	f := newFixture(t)
	res, body := f.do(t, "GET", "/admin/v1/whoami", secret2, "")
	if res.StatusCode != 200 || !strings.Contains(body, `"actor":"bob"`) {
		t.Errorf("whoami: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("X-Request-Id") == "" || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", res.Header)
	}
	res, body = f.do(t, "GET", "/admin/v1/config", secret, "")
	if res.StatusCode != 200 || !strings.Contains(body, `"revision":"aaaaaaaaaaaa"`) || !strings.Contains(body, `"admin_tokens":2`) {
		t.Errorf("config: %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, secret) || strings.Contains(body, auth.HashKey(secret)) {
		t.Errorf("config summary leaks a credential: %s", body)
	}
}

func TestAChangeIsHandedToTheControllerWithItsAuthor(t *testing.T) {
	f := newFixture(t)
	hdr := map[string]string{"X-Request-Id": "req-12345678"}
	res, body := f.doTo(t, f.srv, "POST", "/admin/v1/config/apply", secret2,
		`{"config":"profile: standard\n","policies":[{"name":"a.yaml","yaml":"x"}],"base":"aaaaaaaaaaaa"}`, hdr)
	if res.StatusCode != 200 || !strings.Contains(body, `"revision":"bbbbbbbbbbbb"`) || !strings.Contains(body, `"warnings":[]`) {
		t.Fatalf("apply: %d %s", res.StatusCode, body)
	}
	if f.control.who != (Actor{ID: "bob", RequestID: "req-12345678", Remote: "127.0.0.1"}) {
		t.Errorf("actor = %+v", f.control.who)
	}
	if g := f.control.gotApply; g.Config != "profile: standard\n" || g.Base != "aaaaaaaaaaaa" || len(g.Policies) != 1 || g.Policies[0] != (File{"a.yaml", "x"}) {
		t.Errorf("request = %+v", g)
	}
	if _, body := f.do(t, "POST", "/admin/v1/config/rollback", secret, `{"revision":"cccccccccccc","base":"aaaaaaaaaaaa"}`); !strings.Contains(body, "bbbbbbbbbbbb") ||
		f.control.gotRoll != (RollbackRequest{"cccccccccccc", "aaaaaaaaaaaa"}) || f.control.who.ID != "alice" {
		t.Errorf("rollback: %s %+v %+v", body, f.control.gotRoll, f.control.who)
	}
	if _, body := f.do(t, "POST", "/admin/v1/config/reload", secret, ""); !strings.Contains(body, "bbbbbbbbbbbb") {
		t.Errorf("reload: %s", body)
	}
	if strings.Join(f.observed, ",") != "config.apply:applied,config.rollback:applied,config.reload:applied" {
		t.Errorf("observed = %v", f.observed)
	}
	// the controller records what it applies: the API adds nothing on success
	if len(f.store.changes) != 0 {
		t.Errorf("the API wrote a record of its own: %+v", f.store.changes)
	}
}

func TestBadRequestsNeverReachTheController(t *testing.T) {
	f := newFixture(t)
	big := `{"config":"` + strings.Repeat("x", maxBody) + `","base":"aaaaaaaaaaaa"}`
	for name, c := range map[string]struct {
		path, body string
		status     int
		code       string
	}{
		"apply without base":   {"/admin/v1/config/apply", `{"config":"x"}`, 400, "invalid_request"},
		"apply unknown field":  {"/admin/v1/config/apply", `{"config":"x","base":"a","dry_run":true}`, 400, "invalid_request"},
		"apply not json":       {"/admin/v1/config/apply", `profile: x`, 400, "invalid_request"},
		"apply empty body":     {"/admin/v1/config/apply", ``, 400, "invalid_request"},
		"apply too large":      {"/admin/v1/config/apply", big, 413, "too_large"},
		"rollback no base":     {"/admin/v1/config/rollback", `{"revision":"cccccccccccc"}`, 400, "invalid_request"},
		"rollback bad id":      {"/admin/v1/config/rollback", `{"revision":"../etc","base":"aaaaaaaaaaaa"}`, 400, "invalid_request"},
		"rollback active":      {"/admin/v1/config/rollback", `{"revision":"active","base":"aaaaaaaaaaaa"}`, 400, "invalid_request"},
		"validate unknown key": {"/admin/v1/config/validate", `{"conf":"x"}`, 400, "invalid_request"},
	} {
		res, body := f.do(t, "POST", c.path, secret, c.body)
		if res.StatusCode != c.status || errCode(t, body) != c.code {
			t.Errorf("%s: %d %s", name, res.StatusCode, body)
		}
	}
	if f.control.calls != 0 || len(f.store.changes) != 0 || len(f.observed) != 0 {
		t.Errorf("a bad request had effects: calls=%d changes=%+v observed=%v", f.control.calls, f.store.changes, f.observed)
	}
}

func TestARefusedChangeIsRecordedWithItsCode(t *testing.T) {
	f := newFixture(t)
	f.control.apply = func(Actor, ApplyRequest) (Result, error) {
		return Result{}, &Rejection{Code: "invalid_configuration", Message: "models[0]: bad"}
	}
	res, body := f.do(t, "POST", "/admin/v1/config/apply", secret, `{"config":"x","base":"aaaaaaaaaaaa"}`)
	if res.StatusCode != http.StatusUnprocessableEntity || errCode(t, body) != "invalid_configuration" || !strings.Contains(body, "models[0]: bad") {
		t.Errorf("apply: %d %s", res.StatusCode, body)
	}
	if len(f.store.changes) != 1 {
		t.Fatalf("changes = %+v", f.store.changes)
	}
	c := f.store.changes[0]
	if c.Outcome != store.OutcomeRejected || c.Actor != "alice" || c.Action != ActionApply || !strings.Contains(string(c.Detail), "invalid_configuration") ||
		c.RequestID == "" || c.RemoteAddr != "127.0.0.1" || c.EventID == "" || !c.OccurredAt.Equal(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("record = %+v", c)
	}
	// a rollback names the revision it wanted
	f.control.rollback = func(Actor, RollbackRequest) (Result, error) {
		return Result{}, &Rejection{Code: "credentials_would_return", Message: "x", Status: http.StatusConflict}
	}
	res, _ = f.do(t, "POST", "/admin/v1/config/rollback", secret2, `{"revision":"cccccccccccc","base":"aaaaaaaaaaaa"}`)
	if res.StatusCode != http.StatusConflict || len(f.store.changes) != 2 || f.store.changes[1].Target != "cccccccccccc" || f.store.changes[1].Actor != "bob" || f.store.changes[1].Action != ActionRollback {
		t.Errorf("rollback refusal: %d %+v", res.StatusCode, f.store.changes)
	}
	if strings.Join(f.observed, ",") != "config.apply:rejected,config.rollback:rejected" {
		t.Errorf("observed = %v", f.observed)
	}
	// a refusal still stands when the record of it cannot be written
	f.store.failOn = true
	if res, body = f.do(t, "POST", "/admin/v1/config/apply", secret, `{"config":"x","base":"aaaaaaaaaaaa"}`); res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("refusal with the store down: %d %s", res.StatusCode, body)
	}
}

func TestAChangeThatCannotBeRecordedIsNotMade(t *testing.T) {
	f := newFixture(t)
	f.control.reload = func(Actor) (Result, error) { return Result{}, ErrAuditUnavailable }
	res, body := f.do(t, "POST", "/admin/v1/config/reload", secret, "")
	if res.StatusCode != http.StatusServiceUnavailable || errCode(t, body) != "audit_unavailable" {
		t.Errorf("reload: %d %s", res.StatusCode, body)
	}
	if len(f.store.changes) != 0 {
		t.Errorf("a record was written for a change that did not happen: %+v", f.store.changes)
	}
	if strings.Join(f.observed, ",") != "config.reload:audit_unavailable" {
		t.Errorf("observed = %v", f.observed)
	}
}

func TestAFailureOfTheGatewayIsNotARejection(t *testing.T) {
	f := newFixture(t)
	f.control.reload = func(Actor) (Result, error) { return Result{}, errors.New("database: connection refused") }
	res, body := f.do(t, "POST", "/admin/v1/config/reload", secret, "")
	if res.StatusCode != http.StatusServiceUnavailable || errCode(t, body) != "unavailable" || strings.Contains(body, "connection refused") {
		t.Errorf("reload: %d %s", res.StatusCode, body)
	}
	if len(f.store.changes) != 0 {
		t.Errorf("a failure that changed nothing was recorded as a change: %+v", f.store.changes)
	}
	if strings.Join(f.observed, ",") != "config.reload:failed" {
		t.Errorf("observed = %v", f.observed)
	}
}

func TestWithoutAControllerTheAPIOnlyReads(t *testing.T) {
	f := newFixture(t)
	srv := f.serve(t, nil)
	for _, p := range []string{"/admin/v1/config/reload", "/admin/v1/config/apply", "/admin/v1/config/rollback", "/admin/v1/config/validate"} {
		if res, _ := f.doTo(t, srv, "POST", p, secret, `{"config":"x","base":"a","revision":"cccccccccccc"}`, nil); res.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s = %d", p, res.StatusCode)
		}
	}
	if res, _ := f.doTo(t, srv, "GET", "/admin/v1/whoami", secret, "", nil); res.StatusCode != 200 {
		t.Errorf("whoami = %d", res.StatusCode)
	}
}

func TestValidatePassesTheVerdictThrough(t *testing.T) {
	f := newFixture(t)
	f.control.validate = func(r ApplyRequest) Validation {
		return Validation{Valid: true, Applicable: false, Revision: "dddddddddddd", Reason: "restart_required: database"}
	}
	res, body := f.do(t, "POST", "/admin/v1/config/validate", secret, `{"config":"profile: x"}`)
	var v Validation
	if err := json.Unmarshal([]byte(body), &v); err != nil || res.StatusCode != 200 || !v.Valid || v.Applicable || v.Revision != "dddddddddddd" ||
		!strings.Contains(body, `"errors":[]`) || !strings.Contains(body, `"warnings":[]`) {
		t.Errorf("validate: %d %s", res.StatusCode, body)
	}
	if f.control.gotApply.Config != "profile: x" {
		t.Errorf("request = %+v", f.control.gotApply)
	}
	if len(f.store.changes) != 0 || len(f.observed) != 0 {
		t.Error("validating is not a change")
	}
}

func rev(id string, seq int64, yaml string, policies string) store.StoredRevision {
	return store.StoredRevision{
		Revision: store.Revision{ID: id, Profile: "standard", Version: "v", YAML: []byte(yaml), Policies: []byte(policies)},
		Seq:      seq, FirstLoadedAt: time.Date(2026, 10, int(seq), 8, 0, 0, 0, time.UTC),
	}
}

func TestRevisionsAreListedAndShown(t *testing.T) {
	f := newFixture(t)
	f.store.revisions = []store.StoredRevision{
		rev("111111111111", 1, "a: 1\n", ""),
		rev("222222222222", 2, "a: 2\n", `[{"name":"b.yaml","yaml":"YjogMQ=="},{"name":"a.yaml","yaml":"YTogMQ=="}]`),
	}
	f.store.active = "222222222222"
	res, body := f.do(t, "GET", "/admin/v1/config/revisions?limit=1", secret, "")
	var list struct {
		Revisions []revisionSummary
		Active    string
		Next      string
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || res.StatusCode != 200 || len(list.Revisions) != 1 ||
		list.Revisions[0].Revision != "222222222222" || !list.Revisions[0].Active || list.Active != "222222222222" || list.Next != "2" ||
		strings.Contains(body, "a: 2") {
		t.Fatalf("list: %d %s", res.StatusCode, body)
	}
	_, body = f.do(t, "GET", "/admin/v1/config/revisions", secret, "")
	if !strings.Contains(body, `"active":false`) || strings.Contains(body, `"next"`) {
		t.Errorf("full list: %s", body)
	}

	for _, id := range []string{"222222222222", "active"} {
		res, body = f.do(t, "GET", "/admin/v1/config/revisions/"+id, secret, "")
		var one revisionContent
		if err := json.Unmarshal([]byte(body), &one); err != nil || res.StatusCode != 200 || one.Revision != "222222222222" || !one.Active ||
			one.Config != "a: 2\n" || len(one.Policies) != 2 || one.Policies[0] != (File{"a.yaml", "a: 1"}) || one.Policies[1] != (File{"b.yaml", "b: 1"}) {
			t.Errorf("show %s: %d %s", id, res.StatusCode, body)
		}
	}
	if res, body = f.do(t, "GET", "/admin/v1/config/revisions/111111111111", secret, ""); !strings.Contains(body, `"active":false`) || !strings.Contains(body, `"policies":[]`) {
		t.Errorf("an old revision: %d %s", res.StatusCode, body)
	}
	if res, body = f.do(t, "GET", "/admin/v1/config/revisions/ffffffffffff", secret, ""); res.StatusCode != 404 || errCode(t, body) != "not_found" {
		t.Errorf("unknown: %d %s", res.StatusCode, body)
	}
	for _, id := range []string{"nope", "..%2F..%2Fetc", "222222222222x", "ACTIVE"} {
		if res, _ = f.do(t, "GET", "/admin/v1/config/revisions/"+id, secret, ""); res.StatusCode != 400 {
			t.Errorf("id %q = %d, want 400", id, res.StatusCode)
		}
	}
	// without any activation the running revision is the active one
	f.store.active = ""
	f.holder.Store(&config.Snapshot{Revision: "111111111111", AdminTokens: f.holder.Load().AdminTokens})
	if _, body = f.do(t, "GET", "/admin/v1/config/revisions/active", secret, ""); !strings.Contains(body, `"revision":"111111111111"`) {
		t.Errorf("active without a pointer: %s", body)
	}
	f.store.revisions[1].Policies = []byte(`not json`)
	if res, body = f.do(t, "GET", "/admin/v1/config/revisions/222222222222", secret, ""); res.StatusCode != 500 || errCode(t, body) != "corrupt_revision" {
		t.Errorf("corrupt policies: %d %s", res.StatusCode, body)
	}
	f.store.failOn = true
	for _, p := range []string{"/admin/v1/config/revisions", "/admin/v1/config/revisions/active", "/admin/v1/config/revisions/111111111111"} {
		if res, body = f.do(t, "GET", p, secret, ""); res.StatusCode != 503 || strings.Contains(body, "database down") {
			t.Errorf("%s with the store down: %d %s", p, res.StatusCode, body)
		}
	}
}

func TestDiffBetweenRevisions(t *testing.T) {
	f := newFixture(t)
	f.store.revisions = []store.StoredRevision{
		rev("111111111111", 1, "a: 1\nb: 2\n", `[{"name":"keep.yaml","yaml":"eA=="},{"name":"gone.yaml","yaml":"eQ=="},{"name":"edit.yaml","yaml":"bzE="}]`),
		rev("222222222222", 2, "a: 1\nb: 3\n", `[{"name":"keep.yaml","yaml":"eA=="},{"name":"new.yaml","yaml":"bg=="},{"name":"edit.yaml","yaml":"bzI="}]`),
	}
	f.store.active = "222222222222"
	res, body := f.do(t, "GET", "/admin/v1/config/diff?from=111111111111", secret, "")
	var d struct {
		From, To string
		Files    []textdiff.FileDiff
	}
	if err := json.Unmarshal([]byte(body), &d); err != nil || res.StatusCode != 200 || d.From != "111111111111" || d.To != "222222222222" {
		t.Fatalf("diff: %d %s", res.StatusCode, body)
	}
	got := map[string]string{}
	for _, fd := range d.Files {
		got[fd.Name] = fd.Status
	}
	want := map[string]string{"tavian.yaml": "modified", "policies/edit.yaml": "modified", "policies/gone.yaml": "removed", "policies/new.yaml": "added"}
	if len(got) != len(want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if d.Files[0].Name != "tavian.yaml" || !strings.Contains(d.Files[0].Diff, "-b: 2\n+b: 3\n") {
		t.Errorf("first file: %+v", d.Files[0])
	}
	// the same revision twice: nothing differs
	if _, body = f.do(t, "GET", "/admin/v1/config/diff?from=active&to=222222222222", secret, ""); !strings.Contains(body, `"files":[]`) {
		t.Errorf("identical: %s", body)
	}
	for _, q := range []string{"", "from=nope", "from=111111111111&to=nope"} {
		if res, _ = f.do(t, "GET", "/admin/v1/config/diff?"+q, secret, ""); res.StatusCode != 400 {
			t.Errorf("?%s = %d, want 400", q, res.StatusCode)
		}
	}
	if res, _ = f.do(t, "GET", "/admin/v1/config/diff?from=ffffffffffff", secret, ""); res.StatusCode != 404 {
		t.Errorf("unknown revision = %d", res.StatusCode)
	}
}

func TestChangesListsWhatHappened(t *testing.T) {
	f := newFixture(t)
	f.store.changes = []store.AdminChange{{EventID: "e1", Actor: "alice"}, {EventID: "e2", Actor: "bob"}}
	res, body := f.do(t, "GET", "/admin/v1/changes?limit=10", secret, "")
	var out struct {
		Changes []store.AdminChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || res.StatusCode != 200 || len(out.Changes) != 2 || out.Changes[0].Actor != "bob" {
		t.Fatalf("changes: %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, `"next"`) {
		t.Errorf("the last page offers a next page: %s", body)
	}
	if _, body := f.do(t, "GET", "/admin/v1/changes?limit=1", secret, ""); !strings.Contains(body, `"next":"1"`) {
		t.Errorf("a page that is not the last has no next: %s", body)
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=x", "before=0", "before=x"} {
		for _, p := range []string{"/admin/v1/changes?", "/admin/v1/config/revisions?"} {
			if res, _ := f.do(t, "GET", p+q, secret, ""); res.StatusCode != http.StatusBadRequest {
				t.Errorf("%s%s = %d, want 400", p, q, res.StatusCode)
			}
		}
	}
	f.store.failOn = true
	if res, body := f.do(t, "GET", "/admin/v1/changes", secret, ""); res.StatusCode != http.StatusServiceUnavailable || strings.Contains(body, "database down") {
		t.Errorf("store down: %d %s", res.StatusCode, body)
	}
}

func TestEmptyHistoryIsAnEmptyList(t *testing.T) {
	f := newFixture(t)
	f.store.changes = nil
	if _, body := f.do(t, "GET", "/admin/v1/changes", secret, ""); !strings.Contains(body, `"changes":[]`) {
		t.Errorf("body = %s", body)
	}
}

func TestAuthenticationFailureIsLoggedWithoutTheCredential(t *testing.T) {
	var logs bytes.Buffer
	f := newFixture(t)
	mux := http.NewServeMux()
	Register(mux, Deps{Snap: f.holder, Store: f.store, Log: slog.New(slog.NewTextHandler(&logs, nil))})
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

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/egress"
	"github.com/bredda/tavian/internal/meter"
	"github.com/bredda/tavian/internal/mockllm"
	"github.com/bredda/tavian/internal/provider/openai"
)

type fixture struct {
	gw     *httptest.Server
	admin  *httptest.Server
	sink   *meter.MemorySink
	key    string
	narrow string // key limited to "other-*" models
	conf   string // key cleared up to "confidential"
	top    string // key cleared up to "restricted"
	// partnerCalls counts requests that reached the approved-external backend
	// (only with fixtureSpec.external).
	partnerCalls *atomic.Int64
}

func newFixture(t *testing.T, maxBody int64) *fixture {
	t.Helper()
	return newFixtureSink(t, maxBody, nil)
}

// newFixtureSink lets a test wrap the in-memory sink, e.g. to refuse requests.
func newFixtureSink(t *testing.T, maxBody int64, wrap func(*meter.MemorySink) meter.Sink, opts ...func(*Deps)) *fixture {
	t.Helper()
	return buildFixture(t, fixtureSpec{maxBody: maxBody, wrap: wrap, deps: opts})
}

// fixtureSpec describes a gateway under test; zero values mean defaults.
type fixtureSpec struct {
	maxBody     int64
	maxInflight int          // 0: the default
	backend     http.Handler // nil: the mock backend
	wrap        func(*meter.MemorySink) meter.Sink
	deps        []func(*Deps)
	snap        func(*config.Snapshot) // adjusts the compiled snapshot
	external    bool                   // add an approved-external backend and the models that use it
}

func inflightLimit(n int) int {
	if n == 0 {
		return 256
	}
	return n
}

func buildFixture(t *testing.T, spec fixtureSpec) *fixture {
	t.Helper()
	maxBody, wrap, opts := spec.maxBody, spec.wrap, spec.deps
	backend := spec.backend
	if backend == nil {
		backend = mockllm.HandlerNamed("local")
	}
	llm := httptest.NewServer(backend)
	t.Cleanup(llm.Close)

	key, keyHash, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	narrow, narrowHash, _ := auth.GenerateKey()
	conf, confHash, _ := auth.GenerateKey()
	top, topHash, _ := auth.GenerateKey()

	profile, extraBackends, extraModels := "air-gapped", "", ""
	partnerCalls := &atomic.Int64{}
	if spec.external {
		partner := mockllm.HandlerNamed("partner-eu")
		ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			partnerCalls.Add(1)
			partner.ServeHTTP(w, r)
		}))
		t.Cleanup(ext.Close)
		profile = "controlled-egress"
		extraBackends = fmt.Sprintf(`
  - id: partner
    type: openai
    base_url: %s/v1
    destination_class: approved-external
    max_classification: internal`, ext.URL)
		extraModels = `
  - name: shared
    type: chat
    route:
      - backend: partner
        upstream_model: mock-partner
      - backend: local
        upstream_model: mock-local
  - name: partner-only
    type: chat
    route:
      - backend: partner
        upstream_model: mock-partner`
	}
	yaml := fmt.Sprintf(`
profile: %s
limits:
  max_request_bytes: %d
  max_inflight: %d
backends:
  - id: local
    type: openai
    base_url: %s/v1
    destination_class: internal%s
models:
  - name: llama-70b
    type: chat
    route:
      - backend: local
        upstream_model: mock-upstream
  - name: broken
    type: chat
    route:
      - backend: local
        upstream_model: mock-fail%s
api_keys:
  - id: dev
    hash: %s
    team: research
    application: demo
    allowed_models: ["llama-*", "broken", "shared", "partner-only"]
  - id: narrow
    hash: %s
    team: research
    application: demo
    allowed_models: ["other-*"]
  - id: finance
    hash: %s
    team: finance
    application: ledger
    allowed_models: ["llama-*", "broken", "shared", "partner-only"]
    max_classification: confidential
  - id: vault
    hash: %s
    team: security
    application: vault
    allowed_models: ["llama-*", "broken", "shared", "partner-only"]
    max_classification: restricted
`, profile, maxBody, inflightLimit(spec.maxInflight), llm.URL, extraBackends, extraModels, keyHash, narrowHash, confHash, topHash)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := config.Compile(cfg, []byte(yaml), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if spec.snap != nil {
		spec.snap(snap)
	}
	holder := &config.Holder{}
	holder.Store(snap)

	guard, err := egress.New(cfg.Profile, holder, cfg.Egress.InternalCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	sink := &meter.MemorySink{}
	log := slog.New(slog.DiscardHandler)
	m := NewMetrics()
	deps := Deps{
		Snap:     holder,
		Auth:     auth.APIKeyAuthenticator{Snap: holder},
		Provider: openai.New(guard.HTTPClient(snap.Limits.UpstreamHeaderTimeout), "tavian/test"),
		Sink:     sinkFor(sink, wrap),
		Log:      log,
		Metrics:  m,
	}
	for _, o := range opts {
		o(&deps)
	}
	gw := httptest.NewServer(NewDataHandler(deps))
	t.Cleanup(gw.Close)
	admin := httptest.NewServer(NewAdminHandler(holder, m, nil))
	t.Cleanup(admin.Close)
	return &fixture{gw: gw, admin: admin, sink: sink, key: key, narrow: narrow, conf: conf, top: top, partnerCalls: partnerCalls}
}

func (f *fixture) post(t *testing.T, key, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.gw.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return e.Error.Code
}

const chatBody = `{"model":"llama-70b","messages":[{"role":"user","content":"hello there world"}]}`

func TestChatCompletionEndToEnd(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, chatBody)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id")
	}
	var out struct {
		Model         string `json:"model"`
		ReceivedModel string `json:"x_mock_received_model"`
		Choices       []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ReceivedModel != "mock-upstream" {
		t.Errorf("backend was asked for model %q, want the rewritten upstream name", out.ReceivedModel)
	}
	if out.Model != "llama-70b" {
		t.Errorf("response model = %q, want the name the client asked for", out.Model)
	}
	if len(out.Choices) != 1 || !strings.Contains(out.Choices[0].Message.Content, "hello there world") {
		t.Errorf("choices = %+v", out.Choices)
	}

	evs := f.sink.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	e := evs[0]
	if e.Model != "llama-70b" || e.UpstreamModel != "mock-upstream" || e.Backend != "local" ||
		e.KeyID != "dev" || e.Team != "research" || e.Outcome != "ok" || e.Status != 200 {
		t.Errorf("event = %+v", e)
	}
	if !e.UsageKnown || e.InputTokens != 3 || e.OutputTokens == 0 {
		t.Errorf("usage = %+v", e)
	}
	if e.Revision == "" || e.RequestID != resp.Header.Get("X-Request-Id") || e.EventID == "" {
		t.Errorf("identifiers = %+v", e)
	}
	if e.CostMicroEUR != nil || e.EnergyWh != nil || e.CO2eGrams != nil {
		t.Error("cost/energy/carbon must be nil until configured")
	}
}

func TestChatCompletionStreaming(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, `{"model":"llama-70b","stream":true,"messages":[{"role":"user","content":"stream me please"}]}`)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "data: [DONE]") {
		t.Errorf("stream incomplete: %q", body)
	}
	if strings.Contains(string(body), `"model":"mock-upstream"`) || !strings.Contains(string(body), `"model":"llama-70b"`) {
		t.Errorf("stream chunks must carry the client's model name: %q", body)
	}
	evs := f.sink.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	if !evs[0].Streamed || !evs[0].UsageKnown || evs[0].InputTokens != 3 {
		t.Errorf("event = %+v (gateway must force include_usage so streams are metered)", evs[0])
	}
}

func TestAuthFailures(t *testing.T) {
	f := newFixture(t, 0)
	for name, key := range map[string]string{"missing": "", "wrong": "tav_nope"} {
		resp := f.post(t, key, chatBody)
		if resp.StatusCode != 401 || errorCode(t, resp) != "invalid_api_key" {
			t.Errorf("%s: status = %d", name, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate", name)
		}
	}
	if n := len(f.sink.Events()); n != 0 {
		t.Errorf("unauthenticated requests must not produce usage events, got %d", n)
	}
}

func TestModelAuthorization(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.narrow, chatBody)
	if resp.StatusCode != 403 || errorCode(t, resp) != "model_not_allowed" {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if len(f.sink.Events()) != 0 {
		t.Error("denied request must not reach a backend")
	}
}

func TestUnknownModel(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, `{"model":"llama-does-not-exist","messages":[]}`)
	if resp.StatusCode != 404 || errorCode(t, resp) != "model_not_found" {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestInvalidRequests(t *testing.T) {
	f := newFixture(t, 0)
	for name, body := range map[string]string{
		"not json":     `nope`,
		"no model":     `{"messages":[]}`,
		"bad stream":   `{"model":"llama-70b","stream":"yes"}`,
		"empty object": `{}`,
	} {
		resp := f.post(t, f.key, body)
		if resp.StatusCode != 400 {
			t.Errorf("%s: status = %d", name, resp.StatusCode)
		}
	}
}

func TestRequestTooLarge(t *testing.T) {
	f := newFixture(t, 256)
	resp := f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":"`+strings.Repeat("a", 1000)+`"}]}`)
	if resp.StatusCode != 413 || errorCode(t, resp) != "request_too_large" {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestUpstreamErrorIsRelayedAndMetered(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, `{"model":"broken","messages":[]}`)
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want the backend's 500 relayed", resp.StatusCode)
	}
	evs := f.sink.Events()
	if len(evs) != 1 || evs[0].Outcome != "upstream_error" || evs[0].UsageKnown {
		t.Errorf("events = %+v", evs)
	}
}

func TestModelsListIsFilteredByKey(t *testing.T) {
	f := newFixture(t, 0)
	list := func(key string) []string {
		req, _ := http.NewRequest(http.MethodGet, f.gw.URL+"/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Data []struct{ ID string } `json:"data"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		var ids []string
		for _, m := range out.Data {
			ids = append(ids, m.ID)
		}
		return ids
	}
	if got := strings.Join(list(f.key), ","); got != "broken,llama-70b" {
		t.Errorf("dev models = %q", got)
	}
	if got := list(f.narrow); len(got) != 0 {
		t.Errorf("narrow key must see no models, got %v", got)
	}

	resp, err := http.Get(f.gw.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("unauthenticated /v1/models status = %d", resp.StatusCode)
	}
}

func TestRequestIDHandling(t *testing.T) {
	f := newFixture(t, 0)
	req, _ := http.NewRequest(http.MethodPost, f.gw.URL+"/v1/chat/completions", bytes.NewReader([]byte(chatBody)))
	req.Header.Set("Authorization", "Bearer "+f.key)
	req.Header.Set("X-Request-Id", "client-supplied-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Request-Id"); got != "client-supplied-123" {
		t.Errorf("valid client id should be kept, got %q", got)
	}

	req2, _ := http.NewRequest(http.MethodPost, f.gw.URL+"/v1/chat/completions", bytes.NewReader([]byte(chatBody)))
	req2.Header.Set("Authorization", "Bearer "+f.key)
	req2.Header.Set("X-Request-Id", "bad id with spaces\tand tabs")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if got := resp2.Header.Get("X-Request-Id"); got == "" || strings.Contains(got, " ") {
		t.Errorf("invalid client id must be replaced, got %q", got)
	}
}

func TestUnknownRouteIsJSON(t *testing.T) {
	f := newFixture(t, 0)
	resp, err := http.Get(f.gw.URL + "/v1/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 || errorCode(t, resp) != "not_found" {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestAdminEndpoints(t *testing.T) {
	f := newFixture(t, 0)
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(f.admin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s status = %d", path, resp.StatusCode)
		}
	}
	// Generate one request so metrics have samples.
	f.post(t, f.key, chatBody)
	resp, err := http.Get(f.admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, want := range []string{
		`tavian_requests_total{outcome="ok",route="chat_completions"} 1`,
		`tavian_tokens_total{backend="local",direction="input",model="llama-70b"} 3`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(string(b), "tav_") {
		t.Error("metrics must not contain key material")
	}
}

func TestReadyzWithoutSnapshot(t *testing.T) {
	ts := httptest.NewServer(NewAdminHandler(&config.Holder{}, NewMetrics(), nil))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func sinkFor(m *meter.MemorySink, wrap func(*meter.MemorySink) meter.Sink) meter.Sink {
	if wrap == nil {
		return m
	}
	return wrap(m)
}

// refusingSink records events but reports that none can be admitted.
type refusingSink struct{ *meter.MemorySink }

func (refusingSink) Admit() error { return meter.ErrAuditUnavailable }

func TestChatIsRefusedWhenAuditTrailCannotRecord(t *testing.T) {
	f := newFixtureSink(t, 1<<20, func(m *meter.MemorySink) meter.Sink { return refusingSink{m} })

	resp := f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if got := errorCode(t, resp); got != "audit_unavailable" {
		t.Errorf("error code = %q", got)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After")
	}
	if n := len(f.sink.Events()); n != 0 {
		t.Errorf("a refused request must not reach the backend or be metered, got %d events", n)
	}
	// Unauthenticated callers learn nothing about the audit state.
	resp2 := f.post(t, "", `{}`)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", resp2.StatusCode)
	}
}

func TestReadyzReflectsAuditTrail(t *testing.T) {
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{})
	srv := httptest.NewServer(NewAdminHandler(holder, NewMetrics(), refusingSink{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want 503 when events cannot be recorded", resp.StatusCode)
	}
}

// Every data-plane operation in the OpenAPI description must be routed: this
// catches the spec drifting from the handlers.
func TestOpenAPIOperationsAreRouted(t *testing.T) {
	f := newFixture(t, 1<<20)
	resp, err := http.Get(f.gw.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/openapi.yaml = %d", resp.StatusCode)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Tags []string `yaml:"tags"`
		} `yaml:"paths"`
	}
	if err := yaml.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for path, ops := range doc.Paths {
		for method, op := range ops {
			if slices.Contains(op.Tags, "Operations") { // served by the admin listener
				continue
			}
			req, _ := http.NewRequest(strings.ToUpper(method), f.gw.URL+path, nil)
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			// No key: a routed operation answers 401, an unrouted one 404/405.
			if r.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s answered %d without a key, want 401: is it routed?", method, path, r.StatusCode)
			}
			checked++
		}
	}
	if checked < 2 {
		t.Errorf("only %d operations checked", checked)
	}
}

func TestDocsServedByDefaultWithoutAuth(t *testing.T) {
	f := newFixture(t, 1<<20)
	for _, p := range []string{"/docs", "/docs/scalar.js", "/openapi.yaml"} {
		resp, err := http.Get(f.gw.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", p, resp.StatusCode)
		}
	}
}

// stubAuth stands in for the OIDC authenticator: what matters here is how an
// identity that came from a token ends up in the usage event.
type stubAuth struct{ id *auth.Identity }

func (s stubAuth) Authenticate(*http.Request) (*auth.Identity, error) { return s.id, nil }

func TestUsageEventForAnOIDCIdentity(t *testing.T) {
	id := &auth.Identity{Subject: "user-123", Team: "research", Application: "notebook", AllowedModels: []string{"llama-*"}, Method: "oidc", MaxClassification: config.LabelInternal}
	f := newFixtureSink(t, 1<<20, nil, func(d *Deps) { d.Auth = stubAuth{id} })

	resp := f.post(t, "any-token", `{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}`)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	evs := f.sink.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	e := evs[0]
	if e.AuthMethod != "oidc" || e.UserID != "user-123" || e.KeyID != "" || e.Team != "research" || e.Application != "notebook" {
		t.Errorf("event = %+v", e)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), `"key_id"`) {
		t.Errorf("an OIDC event must not carry an empty key_id: %s", raw)
	}

	// The same person may not use a model their groups do not grant.
	resp = f.post(t, "any-token", `{"model":"broken","messages":[]}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status for a model outside the mapped access = %d, want 403", resp.StatusCode)
	}
}

// blockingBackend holds every chat request until release is closed, so tests
// can keep requests in flight.
func blockingBackend(release <-chan struct{}, started chan<- struct{}) http.Handler {
	inner := mockllm.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			started <- struct{}{}
			<-release
		}
		inner.ServeHTTP(w, r)
	})
}

func TestInflightCapRefusesWithRetryAfterAndRecovers(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, maxInflight: 2, backend: blockingBackend(release, started)})
	const body = `{"model":"llama-70b","messages":[{"role":"user","content":"hold"}]}`

	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := f.post(t, f.key, body)
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	<-started
	<-started // both are inside the backend: the gateway is at its cap

	// The third request is refused at once, even before authentication...
	for _, key := range []string{f.key, "", "tav_wrong"} {
		resp := f.post(t, key, body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("key %q: status %d, Retry-After %q; want 503 with Retry-After", key, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	// ...and says so in the OpenAI error format.
	resp := f.post(t, f.key, body)
	if got := errorCode(t, resp); got != "server_busy" {
		t.Errorf("error code = %q, want server_busy", got)
	}
	resp.Body.Close()
	if n := len(f.sink.Events()); n != 0 {
		t.Errorf("refused or still-running requests produced %d events", n)
	}

	close(release)
	wg.Wait()
	close(statuses)
	for st := range statuses {
		if st != http.StatusOK {
			t.Errorf("a request already in flight finished with %d", st)
		}
	}
	// Capacity comes back once they are done.
	if resp := f.post(t, f.key, body); resp.StatusCode != http.StatusOK {
		t.Errorf("after recovery: status %d", resp.StatusCode)
	}
}

func TestInflightGaugeAndOutcomeMetric(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, maxInflight: 1, backend: blockingBackend(release, started)})
	const body = `{"model":"llama-70b","messages":[{"role":"user","content":"hold"}]}`

	done := make(chan struct{})
	go func() {
		resp := f.post(t, f.key, body)
		resp.Body.Close()
		close(done)
	}()
	<-started
	f.post(t, f.key, body).Body.Close() // refused

	metrics := func() string {
		resp, err := http.Get(f.admin.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	m := metrics()
	if !strings.Contains(m, "tavian_inflight_requests 1") {
		t.Errorf("gauge not 1 while a request is held:\n%s", grepLines(m, "tavian_inflight"))
	}
	if !strings.Contains(m, `tavian_requests_total{outcome="overloaded",route="chat_completions"} 1`) {
		t.Errorf("overloaded outcome not counted:\n%s", grepLines(m, "tavian_requests_total"))
	}
	close(release)
	<-done
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestAPIKeyExpiryMetrics(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{Keys: map[string]*config.APIKey{
		"1": {ID: "never"},
		"2": {ID: "gone", ExpiresAt: now.Add(-time.Hour)},
		"3": {ID: "soon", ExpiresAt: now.Add(36 * time.Hour)},
	}})
	m := NewMetrics()
	m.WatchAPIKeys(holder, func() time.Time { return now })
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	scrape := func() string {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	out := scrape()
	if !strings.Contains(out, "tavian_api_keys_expired 1") || !strings.Contains(out, "tavian_api_keys_next_expiry_seconds 129600") {
		t.Errorf("metrics:\n%s", grepLines(out, "tavian_api_keys"))
	}
	if strings.Contains(out, "soon") || strings.Contains(out, "gone") {
		t.Error("key ids must not appear in metrics")
	}

	// A reload that removes the expiring keys is visible at the next scrape.
	holder.Store(&config.Snapshot{Keys: map[string]*config.APIKey{"1": {ID: "never"}}})
	out = scrape()
	if !strings.Contains(out, "tavian_api_keys_expired 0") || strings.Contains(out, "next_expiry_seconds ") {
		t.Errorf("after reload:\n%s", grepLines(out, "tavian_api_keys"))
	}
}

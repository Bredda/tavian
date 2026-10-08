package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
}

func newFixture(t *testing.T, maxBody int64) *fixture {
	t.Helper()
	llm := httptest.NewServer(mockllm.Handler())
	t.Cleanup(llm.Close)

	key, keyHash, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	narrow, narrowHash, _ := auth.GenerateKey()

	yaml := fmt.Sprintf(`
profile: air-gapped
limits:
  max_request_bytes: %d
backends:
  - id: local
    type: openai
    base_url: %s/v1
    destination_class: internal
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
        upstream_model: mock-fail
api_keys:
  - id: dev
    hash: %s
    team: research
    application: demo
    allowed_models: ["llama-*", "broken"]
  - id: narrow
    hash: %s
    team: research
    application: demo
    allowed_models: ["other-*"]
`, maxBody, llm.URL, keyHash, narrowHash)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := config.Compile(cfg, []byte(yaml), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
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
	gw := httptest.NewServer(NewDataHandler(Deps{
		Snap:     holder,
		Auth:     auth.APIKeyAuthenticator{Snap: holder},
		Provider: openai.New(guard.HTTPClient(snap.Limits.UpstreamHeaderTimeout), "tavian/test"),
		Sink:     sink,
		Log:      log,
		Metrics:  m,
	}))
	t.Cleanup(gw.Close)
	admin := httptest.NewServer(NewAdminHandler(holder, m))
	t.Cleanup(admin.Close)
	return &fixture{gw: gw, admin: admin, sink: sink, key: key, narrow: narrow}
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
		Model   string `json:"model"`
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Model != "mock-upstream" {
		t.Errorf("upstream saw model %q, want the rewritten upstream name", out.Model)
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
	ts := httptest.NewServer(NewAdminHandler(&config.Holder{}, NewMetrics()))
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

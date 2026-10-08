package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/config"
)

func backend(t *testing.T, rawURL, credential string) *config.Backend {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Backend{ID: "b", URL: u, Credential: credential}
}

func TestPeekChat(t *testing.T) {
	m, s, err := PeekChat([]byte(`{"model":"llama","stream":true,"messages":[]}`))
	if err != nil || m != "llama" || !s {
		t.Fatalf("got %q %v %v", m, s, err)
	}
	for _, bad := range []string{``, `not json`, `{}`, `{"model":""}`, `{"model":"x","stream":"yes"}`} {
		if _, _, err := PeekChat([]byte(bad)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("PeekChat(%q) err = %v, want ErrInvalidRequest", bad, err)
		}
	}
}

func TestRewriteChat(t *testing.T) {
	out, err := RewriteChat([]byte(`{"model":"alias","messages":[{"role":"user","content":"hi"}],"temperature":0.2,"x_custom":{"a":1}}`), "upstream/model")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["model"]) != `"upstream/model"` {
		t.Errorf("model = %s", m["model"])
	}
	for _, k := range []string{"messages", "temperature", "x_custom"} {
		if _, ok := m[k]; !ok {
			t.Errorf("field %q was dropped", k)
		}
	}
	if _, ok := m["stream_options"]; ok {
		t.Error("stream_options must not be added to non-streaming requests")
	}
}

func TestRewriteChatForcesUsageOnStreams(t *testing.T) {
	out, err := RewriteChat([]byte(`{"model":"a","stream":true,"stream_options":{"include_usage":false,"other":1}}`), "u")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		StreamOptions map[string]any `json:"stream_options"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.StreamOptions["include_usage"] != true || m.StreamOptions["other"] != float64(1) {
		t.Errorf("stream_options = %v", m.StreamOptions)
	}
}

func TestChatCompletionsNonStreaming(t *testing.T) {
	var gotAuth, gotPath, gotUA, gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotUA = r.Header.Get("Authorization"), r.URL.Path, r.UserAgent()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "leak=1")
		io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":2}}}`)
	}))
	defer up.Close()

	c := New(up.Client(), "tavian/test")
	rec := httptest.NewRecorder()
	res, err := c.ChatCompletions(context.Background(), rec, backend(t, up.URL+"/v1", "backend-secret"), []byte(`{"model":"m"}`), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer backend-secret" {
		t.Errorf("upstream Authorization = %q", gotAuth)
	}
	if gotUA != "tavian/test" {
		t.Errorf("user agent = %q", gotUA)
	}
	if gotBody != `{"model":"m"}` {
		t.Errorf("body = %q", gotBody)
	}
	if !res.Started || res.Status != 200 || res.Streamed {
		t.Errorf("result = %+v", res)
	}
	want := Usage{Input: 11, Output: 7, Cached: 3, Reasoning: 2, Known: true}
	if res.Usage != want {
		t.Errorf("usage = %+v, want %+v", res.Usage, want)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("upstream Set-Cookie must not be relayed")
	}
	if !strings.Contains(rec.Body.String(), `"prompt_tokens":11`) {
		t.Errorf("body not relayed: %s", rec.Body)
	}
}

func TestChatCompletionsNeverForwardsClientCredentials(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `{}`)
	}))
	defer up.Close()
	c := New(up.Client(), "ua")
	// No backend credential configured: nothing at all may be sent.
	if _, err := c.ChatCompletions(context.Background(), httptest.NewRecorder(), backend(t, up.URL, ""), []byte(`{}`), "", ""); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none", gotAuth)
	}
}

func TestChatCompletionsStreaming(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		// Split one event across writes to exercise line reassembly.
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n")
		fl.Flush()
		io.WriteString(w, "data: {\"choices\":[],\"usa")
		fl.Flush()
		io.WriteString(w, "ge\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\r\n\r\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()

	c := New(up.Client(), "ua")
	rec := httptest.NewRecorder()
	res, err := c.ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{"stream":true}`), "text/event-stream", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Streamed {
		t.Error("expected streamed result")
	}
	if res.Usage != (Usage{Input: 5, Output: 2, Known: true}) {
		t.Errorf("usage = %+v", res.Usage)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "[DONE]") || !strings.Contains(body, `"content":"hi"`) {
		t.Errorf("stream not relayed intact: %q", body)
	}
	if rec.Header().Get("X-Accel-Buffering") != "no" {
		t.Error("buffering must be disabled for SSE")
	}
	if res.TTFB <= 0 || res.TTFB > 5*time.Second {
		t.Errorf("ttfb = %v", res.TTFB)
	}
}

func TestChatCompletionsUpstreamErrorStatusIsRelayed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"message":"slow down"}}`)
	}))
	defer up.Close()
	rec := httptest.NewRecorder()
	res, err := New(up.Client(), "ua").ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{}`), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 429 || rec.Code != 429 || rec.Header().Get("Retry-After") != "3" {
		t.Errorf("status=%d code=%d retry-after=%q", res.Status, rec.Code, rec.Header().Get("Retry-After"))
	}
	if res.Usage.Known {
		t.Error("no usage expected on error responses")
	}
}

func TestChatCompletionsUnreachableBackend(t *testing.T) {
	up := httptest.NewServer(http.NotFoundHandler())
	u := up.URL
	up.Close() // nothing listens any more
	rec := httptest.NewRecorder()
	res, err := New(http.DefaultClient, "ua").ChatCompletions(context.Background(), rec, backend(t, u, ""), []byte(`{}`), "", "")
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
	if res.Started {
		t.Error("nothing must have been written to the client")
	}
	if rec.Body.Len() != 0 {
		t.Error("response body must be empty so the caller can write its own error")
	}
}

func TestSSETapDropsOversizedLines(t *testing.T) {
	tap := &sseTap{}
	out := tap.filter([]byte(strings.Repeat("x", maxSSELine+1)))
	if len(tap.buf) != 0 || len(out) != maxSSELine+1 {
		t.Error("an oversized partial line must be passed through, not held")
	}
	tap.filter([]byte("data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n"))
	if !tap.usage.Known {
		t.Error("tap must keep working after dropping a line")
	}
}

func TestResponseModelIsPutBackToTheClientsName(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","model":"meta/llama-upstream","choices":[{"index":0}],"usage":{"prompt_tokens":4,"completion_tokens":2},"x_vendor":{"keep":true}}`)
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	res, err := New(up.Client(), "ua").ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{}`), "", "llama-70b")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if string(out["model"]) != `"llama-70b"` {
		t.Errorf("model = %s", out["model"])
	}
	for _, k := range []string{"id", "choices", "usage", "x_vendor"} {
		if _, ok := out[k]; !ok {
			t.Errorf("field %q was lost", k)
		}
	}
	if res.Usage != (Usage{Input: 4, Output: 2, Known: true}) {
		t.Errorf("usage = %+v", res.Usage)
	}
}

func TestModelRewriteLeavesErrorsAndModellessBodiesAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"error status":  {http.StatusBadRequest, `{"error":{"message":"bad","model":"upstream"}}`},
		"no model":      {http.StatusOK, `{"id":"c1","choices":[]}`},
		"not an object": {http.StatusOK, `["model"]`},
	} {
		t.Run(name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer up.Close()
			rec := httptest.NewRecorder()
			if _, err := New(up.Client(), "ua").ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{}`), "", "client-name"); err != nil {
				t.Fatal(err)
			}
			if rec.Body.String() != tc.body {
				t.Errorf("body changed: %q", rec.Body.String())
			}
		})
	}
}

func TestStreamedChunksCarryTheClientsModelName(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		io.WriteString(w, ": keep-alive comment\n\n")
		io.WriteString(w, "data: {\"model\":\"up\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
		fl.Flush()
		// An event split mid-line, with CRLF endings.
		io.WriteString(w, "data: {\"model\":\"up\",\"choices\":[],\"usa")
		fl.Flush()
		io.WriteString(w, "ge\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\r\n\r\n")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{}}]}\n\n") // no model field
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	res, err := New(up.Client(), "ua").ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{}`), "text/event-stream", "client-name")
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"up"`) {
		t.Errorf("the backend's model name leaked: %q", body)
	}
	if n := strings.Count(body, `"model":"client-name"`); n != 2 {
		t.Errorf("model rewritten %d times, want 2: %q", n, body)
	}
	for _, want := range []string{": keep-alive comment\n\n", "data: {\"choices\":[{\"delta\":{}}]}\n\n", "data: [DONE]\n\n", "\r\n\r\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("stream lost %q: %q", want, body)
		}
	}
	if res.Usage != (Usage{Input: 5, Output: 2, Known: true}) {
		t.Errorf("usage = %+v", res.Usage)
	}
}

func TestStreamEndingWithoutNewlineIsFlushed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: [DONE]") // no trailing newline
	}))
	defer up.Close()
	rec := httptest.NewRecorder()
	if _, err := New(up.Client(), "ua").ChatCompletions(context.Background(), rec, backend(t, up.URL, ""), []byte(`{}`), "text/event-stream", "m"); err != nil {
		t.Fatal(err)
	}
	if rec.Body.String() != "data: [DONE]" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

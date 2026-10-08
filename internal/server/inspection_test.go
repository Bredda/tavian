package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/inspect"
)

// Sensitive values that must never show up anywhere but in the request that
// carries them and in the model's answer to it.
const (
	canaryEmail = "canary.person@canary-corp.example"
	canaryText  = "CANARY-PROMPT-TEXT-7731"
)

func metricsText(t *testing.T, f *fixture) string {
	t.Helper()
	resp, err := http.Get(f.admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestInspectionFindingsAreSummarisedInTheUsageEvent(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":"mail `+canaryEmail+` and `+canaryEmail+`"}]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	evs := f.sink.Events()
	if len(evs) != 1 || evs[0].Inspection == nil {
		t.Fatalf("events = %+v", evs)
	}
	in := evs[0].Inspection
	if in.Status != inspect.StatusOK || in.Findings != 2 || in.Counts["pii.email"] != 2 || in.Detectors["pii.email"] == "" {
		t.Errorf("inspection summary = %+v", in)
	}

	m := metricsText(t, f)
	for _, want := range []string{
		`tavian_inspections_total{status="ok"} 1`,
		`tavian_inspection_findings_total{subtype="email",type="pii"} 2`,
		`tavian_inspection_duration_seconds_count 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, grepLines(m, "tavian_inspection"))
		}
	}
}

func TestInspectionSeesEveryStringOfTheBody(t *testing.T) {
	f := newFixture(t, 0)
	// tool-call arguments, a prediction and a vendor extension parameter
	f.post(t, f.key, `{"model":"llama-70b",
	  "messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"to\":\"`+canaryEmail+`\"}"}}]}],
	  "prediction":{"type":"content","content":"`+canaryEmail+`"},
	  "documents":[{"text":"`+canaryEmail+`"}]}`).Body.Close()
	evs := f.sink.Events()
	if len(evs) != 1 || evs[0].Inspection == nil || evs[0].Inspection.Findings != 3 {
		t.Fatalf("events = %+v", evs)
	}
}

func TestMultimodalRequestsAreRefusedAndRecorded(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`)
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != inspect.GapMultimodal {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	evs := f.sink.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want one recording the refusal", len(evs))
	}
	e := evs[0]
	if e.Outcome != "inspection_blocked" || e.Status != 400 || e.Backend != "" || e.Inspection == nil ||
		e.Inspection.Status != inspect.StatusFailed || e.Inspection.Reason != inspect.GapMultimodal {
		t.Errorf("event = %+v inspection = %+v", e, e.Inspection)
	}
	if !strings.Contains(metricsText(t, f), `tavian_requests_total{outcome="inspection_blocked",route="chat_completions"} 1`) {
		t.Error("blocked outcome not counted")
	}
}

type failingDetector struct{ err error }

func (failingDetector) Name() string                 { return "test.failing" }
func (failingDetector) Version() string              { return "1" }
func (failingDetector) Health(context.Context) error { return nil }
func (d failingDetector) Inspect(context.Context, inspect.Request) ([]inspect.Finding, error) {
	return nil, d.err
}

func TestDetectorFailureBlocksTheRequest(t *testing.T) {
	var backendCalls int
	var mu sync.Mutex
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		backendCalls++
		mu.Unlock()
		w.WriteHeader(200)
	})
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: backend, snap: func(s *config.Snapshot) {
		s.Inspector = inspect.NewWith(time.Second, []byte("0123456789abcdef"), failingDetector{err: context.DeadlineExceeded})
	}})
	resp := f.post(t, f.key, chatBody)
	if resp.StatusCode != http.StatusServiceUnavailable || errorCode(t, resp) != inspect.CodeFailed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if backendCalls != 0 {
		t.Errorf("the backend was called %d times for a request that could not be inspected", backendCalls)
	}
	if evs := f.sink.Events(); len(evs) != 1 || evs[0].Outcome != "inspection_blocked" || evs[0].Inspection.Status != inspect.StatusFailed {
		t.Errorf("events = %+v", evs)
	}
	if !strings.Contains(metricsText(t, f), `tavian_inspections_total{status="failed"} 1`) {
		t.Error("failure not counted")
	}
}

func TestInspectionCanBeDisabledExplicitly(t *testing.T) {
	off := false
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, snap: func(s *config.Snapshot) {
		e, err := inspect.New(inspect.Config{Enabled: &off}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.Inspector = e
	}})
	resp := f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":[{"type":"image_url"}]}]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if evs := f.sink.Events(); len(evs) != 1 || evs[0].Inspection == nil || evs[0].Inspection.Status != inspect.StatusSkipped {
		t.Errorf("events = %+v", evs)
	}
}

// lockedBuffer collects log output from the handler's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestNoContentLeaksThroughObservability sends sensitive values down every
// path (answered, streamed, backend error, refused, inspection failure) and
// checks that none of them appears in the logs, the metrics, the usage events
// or the error bodies. SECURITY.md T12.
func TestNoContentLeaksThroughObservability(t *testing.T) {
	logs := &lockedBuffer{}
	debugLog := func(d *Deps) {
		d.Log = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, deps: []func(*Deps){debugLog}})

	prompt := func(model, extra string) string {
		return `{"model":"` + model + `",` + extra + `"messages":[{"role":"user","content":"` + canaryText + ` ` + canaryEmail + `"}]}`
	}
	bodies := map[string]string{
		"answered":           prompt("llama-70b", ""),
		"streamed":           prompt("llama-70b", `"stream":true,`),
		"backend error":      prompt("broken", ""),
		"unknown model":      prompt("nope", ""),
		"denied model":       prompt("other-1", ""),
		"multimodal refusal": `{"model":"llama-70b","messages":[{"role":"user","content":[{"type":"text","text":"` + canaryText + canaryEmail + `"},{"type":"image_url"}]}]}`,
		"malformed":          `{"model":"llama-70b","messages":[{"content":"` + canaryText + canaryEmail,
	}
	var errorBodies []string
	for name, body := range bodies {
		resp := f.post(t, f.key, body)
		b, _ := io.ReadAll(resp.Body)
		if name == "answered" || name == "streamed" {
			continue // the model may echo the prompt back to the caller who sent it
		}
		errorBodies = append(errorBodies, name+": "+string(b))
	}
	// the same, with an inspection failure
	g := buildFixture(t, fixtureSpec{maxBody: 1 << 20, deps: []func(*Deps){debugLog}, snap: func(s *config.Snapshot) {
		s.Inspector = inspect.NewWith(time.Second, []byte("0123456789abcdef"), failingDetector{err: io.ErrUnexpectedEOF})
	}})
	resp := g.post(t, g.key, prompt("llama-70b", ""))
	b, _ := io.ReadAll(resp.Body)
	errorBodies = append(errorBodies, "inspection failure: "+string(b))

	events, _ := json.Marshal(append(f.sink.Events(), g.sink.Events()...))
	surfaces := map[string]string{
		"logs":    logs.String(),
		"metrics": metricsText(t, f) + metricsText(t, g),
		"events":  string(events),
		"errors":  strings.Join(errorBodies, "\n"),
	}
	for name, text := range surfaces {
		if text == "" {
			t.Errorf("%s: nothing captured, the test would pass for nothing", name)
		}
		for _, canary := range []string{canaryText, canaryEmail, "canary-corp", "canary.person"} {
			if strings.Contains(text, canary) {
				t.Errorf("%s leak %q:\n%.600s", name, canary, text)
			}
		}
	}
	// The detection really happened on the paths that were inspected.
	if !strings.Contains(string(events), `"pii.email"`) {
		t.Error("no event carries an email finding: the canary was not even detected")
	}
}

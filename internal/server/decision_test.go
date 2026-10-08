package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/meter"
)

// decisions returns the decision records the fixture's sink received.
func decisions(f *fixture) []audit.DecisionRecord {
	var out []audit.DecisionRecord
	for _, e := range f.sink.Records() {
		if d, ok := e.(audit.DecisionRecord); ok {
			out = append(out, d)
		}
	}
	return out
}

func errorDecisionID(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var e struct {
		Error struct {
			DecisionID string `json:"decision_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body %q: %v", b, err)
	}
	return e.Error.DecisionID
}

// Every authenticated chat request leaves exactly one decision record, whatever
// became of it, and the caller gets the id of that record in the header and,
// for refusals, in the error body.
func TestEveryAuthenticatedRequestLeavesOneDecisionRecord(t *testing.T) {
	f := newFixture(t, 4096)
	big := `{"model":"llama-70b","messages":[{"role":"user","content":"` + strings.Repeat("x", 5000) + `"}]}`
	cases := []struct {
		name    string
		key     string
		body    string
		status  int
		outcome string
		reason  string
	}{
		{"served", f.key, chatBody, 200, audit.OutcomeServed, "SERVED"},
		{"streamed", f.key, `{"model":"llama-70b","stream":true,"messages":[{"role":"user","content":"hi there"}]}`, 200, audit.OutcomeServed, "SERVED"},
		{"backend error", f.key, `{"model":"broken","messages":[{"role":"user","content":"hi there"}]}`, 500, audit.OutcomeFailed, "UPSTREAM_ERROR"},
		{"model not allowed", f.narrow, chatBody, 403, audit.OutcomeRefused, "MODEL_NOT_ALLOWED"},
		{"model not found", f.key, `{"model":"llama-nope","messages":[{"role":"user","content":"hi"}]}`, 404, audit.OutcomeRefused, "MODEL_NOT_FOUND"},
		{"malformed body", f.key, `{"model":`, 400, audit.OutcomeRefused, "INVALID_REQUEST"},
		{"missing model", f.key, `{"messages":[]}`, 400, audit.OutcomeRefused, "INVALID_REQUEST"},
		{"too large", f.key, big, 413, audit.OutcomeRefused, "REQUEST_TOO_LARGE"},
		{"multimodal", f.key, `{"model":"llama-70b","messages":[{"role":"user","content":[{"type":"image_url"}]}]}`, 400, audit.OutcomeRefused, "MULTIMODAL_NOT_INSPECTABLE"},
	}
	for _, c := range cases {
		before := len(decisions(f))
		resp := f.post(t, c.key, c.body)
		hdr := resp.Header.Get("X-Tavian-Decision-Id")
		var bodyID string
		if c.status >= 400 && c.reason != "UPSTREAM_ERROR" {
			bodyID = errorDecisionID(t, resp)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		recs := decisions(f)
		if resp.StatusCode != c.status || len(recs) != before+1 {
			t.Errorf("%s: status = %d records +%d, want %d and +1", c.name, resp.StatusCode, len(recs)-before, c.status)
			continue
		}
		d := recs[len(recs)-1]
		if d.Outcome != c.outcome || d.ReasonCode != c.reason || d.Status != c.status {
			t.Errorf("%s: record = %s/%s/%d, want %s/%s/%d", c.name, d.Outcome, d.ReasonCode, d.Status, c.outcome, c.reason, c.status)
		}
		if hdr == "" || hdr != d.DecisionID {
			t.Errorf("%s: header decision id %q, record %q", c.name, hdr, d.DecisionID)
		}
		if bodyID != "" && bodyID != d.DecisionID {
			t.Errorf("%s: body decision id %q, record %q", c.name, bodyID, d.DecisionID)
		}
		if d.RequestID != resp.Header.Get("X-Request-Id") || d.Team != "research" || d.KeyID == "" || d.Revision == "" || d.AuthMethod != "api_key" {
			t.Errorf("%s: record = %+v", c.name, d)
		}
	}
}

func TestUsageEventPointsAtItsDecisionRecord(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, chatBody)
	resp.Body.Close()
	evs, recs := f.sink.Events(), decisions(f)
	if len(evs) != 1 || len(recs) != 1 {
		t.Fatalf("events = %d records = %d", len(evs), len(recs))
	}
	if evs[0].DecisionID == "" || evs[0].DecisionID != recs[0].DecisionID || evs[0].DecisionID != resp.Header.Get("X-Tavian-Decision-Id") {
		t.Errorf("usage %q, record %q, header %q", evs[0].DecisionID, recs[0].DecisionID, resp.Header.Get("X-Tavian-Decision-Id"))
	}
	if recs[0].Backend != "local" || recs[0].UpstreamModel != "mock-upstream" || recs[0].Model != "llama-70b" {
		t.Errorf("record = %+v", recs[0])
	}
}

// Before the caller is known nothing is recorded: anyone could fill the audit
// trail otherwise.
func TestAnonymousRefusalsLeaveNoRecord(t *testing.T) {
	f := newFixture(t, 0)
	for name, key := range map[string]string{"missing": "", "wrong": "tav_nope"} {
		resp := f.post(t, key, chatBody)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("%s: status = %d", name, resp.StatusCode)
		}
		if resp.Header.Get("X-Tavian-Decision-Id") != "" {
			t.Errorf("%s: a decision id was issued for an anonymous request", name)
		}
	}
	if n := len(f.sink.Records()); n != 0 {
		t.Errorf("records = %d after anonymous requests", n)
	}
}

func TestNoRecordNoIdWhenTheAuditTrailCannotTakeTheRequest(t *testing.T) {
	f := newFixtureSink(t, 1<<20, func(m *meter.MemorySink) meter.Sink { return refusingSink{m} })
	resp := f.post(t, f.key, chatBody)
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("X-Tavian-Decision-Id") != "" || len(f.sink.Records()) != 0 {
		t.Errorf("status = %d id = %q records = %d", resp.StatusCode, resp.Header.Get("X-Tavian-Decision-Id"), len(f.sink.Records()))
	}
}

// failingDecisions stores usage events but cannot store decision records.
type failingDecisions struct{ *meter.MemorySink }

func (s failingDecisions) Emit(ctx context.Context, e meter.Event) error {
	if e.Kind() == audit.KindDecision {
		return errors.New("disk full")
	}
	return s.MemorySink.Emit(ctx, e)
}

// A refusal whose record cannot be stored fails closed: the caller is told the
// gateway cannot record, and is not handed a decision id that does not exist.
func TestRefusalWithoutARecordFailsClosed(t *testing.T) {
	f := newFixtureSink(t, 1<<20, func(m *meter.MemorySink) meter.Sink { return failingDecisions{m} })
	resp := f.post(t, f.narrow, chatBody) // would be 403
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("X-Tavian-Decision-Id") != "" || resp.Header.Get("Retry-After") == "" {
		t.Errorf("status = %d id = %q retry = %q", resp.StatusCode, resp.Header.Get("X-Tavian-Decision-Id"), resp.Header.Get("Retry-After"))
	}
	if code := errorCode(t, resp); code != "audit_unavailable" {
		t.Errorf("code = %q", code)
	}
	if !strings.Contains(metricsText(t, f), `tavian_requests_total{outcome="audit_unavailable",route="chat_completions"} 1`) {
		t.Error("outcome not counted")
	}
}

// The record carries the details of findings (where, which fingerprint) and
// never a value.
func TestRecordHoldsFindingDetailsButNoValue(t *testing.T) {
	f := newFixture(t, 0)
	f.post(t, f.key, `{"model":"llama-70b","messages":[{"role":"user","content":"pay `+canaryIBAN+` to `+canaryEmail+`"}]}`).Body.Close()
	recs := decisions(f)
	if len(recs) != 1 || len(recs[0].Findings) != 2 {
		t.Fatalf("records = %+v", recs)
	}
	for _, fi := range recs[0].Findings {
		if len(fi.Fingerprint) != 32 || fi.Detector == "" || fi.Location.End <= fi.Location.Start || fi.Location.Field != inspect.FieldContent {
			t.Errorf("finding = %+v", fi)
		}
	}
	if recs[0].Inspection == nil || recs[0].Inspection.Counts["pii.iban"] != 1 {
		t.Errorf("summary = %+v", recs[0].Inspection)
	}
	b, _ := json.Marshal(recs[0])
	for _, v := range []string{canaryIBAN, "FR1420041010050500013M02606", canaryEmail, "canary-corp"} {
		if strings.Contains(string(b), v) {
			t.Errorf("record leaks %q: %s", v, b)
		}
	}
}

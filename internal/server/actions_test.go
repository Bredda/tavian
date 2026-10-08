package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/mockllm"
	"github.com/bredda/tavian/internal/policy"
)

// recorder is a backend that remembers what it was sent.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	inner  http.Handler
}

func newRecorder() *recorder { return &recorder{inner: mockllm.HandlerNamed("local")} }

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, string(b))
		r.mu.Unlock()
		req.Body = io.NopCloser(strings.NewReader(string(b)))
	}
	r.inner.ServeHTTP(w, req)
}

func (r *recorder) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.bodies, "\n")
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func actionPolicy(rules string) policy.Source {
	return policyFile("actions.yaml", `
metadata: { name: acts }
spec:
  scope: { organization: true }
  inspection:
    request:
      on_finding:
`+rules)
}

func TestBlockRuleRefusesWithItsOwnReason(t *testing.T) {
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: rec, policies: []policy.Source{actionPolicy(
		`        - { id: no-secrets, when: 'finding.type == "secret"', action: block, reason: SECRET_IN_PROMPT }`)}})

	// even a key that could not send a secret at all gets the policy's reason
	for name, key := range map[string]string{"default clearance": f.key, "restricted clearance": f.top} {
		resp, _ := f.chat(t, key, "llama-70b", "key "+canarySec)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "blocked_by_policy" {
			t.Fatalf("%s: status = %d", name, resp.StatusCode)
		}
		d := lastDecision(t, f)
		if d.Outcome != audit.OutcomeRefused || d.ReasonCode != "SECRET_IN_PROMPT" || !slices.Contains(d.RulesMatched, "acts/no-secrets") || d.Label != "restricted" {
			t.Errorf("%s: record = %s/%s %v label %s", name, d.Outcome, d.ReasonCode, d.RulesMatched, d.Label)
		}
	}
	if rec.count() != 0 || len(f.sink.Events()) != 0 {
		t.Errorf("a blocked request reached the backend (%d) or was metered (%d)", rec.count(), len(f.sink.Events()))
	}
	if !strings.Contains(metricsText(t, f), `tavian_policy_actions_total{action="block"} 2`) {
		t.Error("blocks not counted")
	}
	// the message names the reason code, never the content
	resp := f.post(t, f.top, chatWith("key "+canarySec))
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "SECRET_IN_PROMPT") || strings.Contains(string(b), canarySec) {
		t.Errorf("body = %s", b)
	}
	// ordinary requests are untouched
	if resp, _ := f.chat(t, f.key, "llama-70b", "hello"); resp.StatusCode != 200 {
		t.Errorf("ordinary: status = %d", resp.StatusCode)
	}
}

func TestRedactSendsPlaceholdersToTheBackend(t *testing.T) {
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: rec, policies: []policy.Source{actionPolicy(
		`        - { id: mask-emails, when: 'finding.subtype == "email"', action: redact }`)}})

	body := `{"model":"llama-70b","temperature":0.2,"messages":[{"role":"system","content":"be brief"},{"role":"user","content":"write to ` + canaryEmail + ` and cc ` + canaryEmail + ` or bob@other.example"}],"x_extra":{"keep":"me"}}`
	resp := f.post(t, f.key, body)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, b)
	}
	sent := rec.all()
	if strings.Contains(sent, "canary") || strings.Contains(sent, "@") {
		t.Errorf("the backend received an address: %s", sent)
	}
	for _, want := range []string{"write to [EMAIL_1] and cc [EMAIL_1] or [EMAIL_2]", `"temperature":0.2`, `"x_extra":{"keep":"me"}`, "be brief"} {
		if !strings.Contains(sent, want) {
			t.Errorf("the backend did not receive %q:\n%s", want, sent)
		}
	}
	if strings.Contains(string(b), "canary") {
		t.Errorf("the answer contains the address: %s", b)
	}
	d := lastDecision(t, f)
	if d.Outcome != audit.OutcomeServed || d.Redactions["pii.email"] != 3 || len(d.RulesMatched) != 1 || d.RulesMatched[0] != "acts/mask-emails" {
		t.Errorf("record = %s %v %v", d.Outcome, d.Redactions, d.RulesMatched)
	}
	if d.Inspection.Counts["pii.email"] != 3 {
		t.Errorf("the summary describes the original request: %+v", d.Inspection)
	}
	if !strings.Contains(metricsText(t, f), `tavian_policy_actions_total{action="redact"} 1`) {
		t.Error("redaction not counted")
	}

	// the streaming path sends the redacted body too
	n := rec.count()
	resp = f.post(t, f.key, `{"model":"llama-70b","stream":true,"messages":[{"role":"user","content":"hi `+canaryEmail+`"}]}`)
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 || rec.count() != n+1 || strings.Contains(rec.bodies[n], "canary") || !strings.Contains(rec.bodies[n], "[EMAIL_1]") {
		t.Errorf("stream: status %d, backend got %s", resp.StatusCode, rec.bodies[len(rec.bodies)-1])
	}
}

// Redacting does not make a request less sensitive: an IBAN replaced by a
// placeholder still keeps the request on internal destinations.
func TestRedactDoesNotChangeTheRoute(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, policies: []policy.Source{actionPolicy(
		`        - { id: mask-ibans, when: 'finding.subtype == "iban"', action: redact }`)}})
	resp, who := f.chat(t, f.conf, "shared", "pay "+canaryIBAN)
	if resp.StatusCode != 200 || who != "local" || f.partnerCalls.Load() != 0 {
		t.Fatalf("status %d answered by %q, external calls %d: the label comes from the original findings", resp.StatusCode, who, f.partnerCalls.Load())
	}
	d := lastDecision(t, f)
	if d.Label != "confidential" || d.Redactions["pii.iban"] != 1 {
		t.Errorf("record = %s %v", d.Label, d.Redactions)
	}
}

func TestRedactionRefusesWhenItCannotBeComplete(t *testing.T) {
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 8 << 20, backend: rec, policies: []policy.Source{actionPolicy(
		`        - { id: mask-emails, when: 'finding.subtype == "email"', action: redact }`)}})
	// more findings than the engine keeps: some could not be replaced
	resp, _ := f.chat(t, f.key, "llama-70b", strings.Repeat("u@b.example ", 1100))
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "redaction_incomplete" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if d := lastDecision(t, f); d.ReasonCode != "REDACTION_INCOMPLETE" || rec.count() != 0 {
		t.Errorf("record = %s, backend calls %d", d.ReasonCode, rec.count())
	}
}

// Replacing a value can reveal one next to it that no detector saw before. The
// gateway looks at what it is about to send, and refuses rather than send it.
func TestRedactionIsVerifiedBeforeSending(t *testing.T) {
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: rec, policies: []policy.Source{actionPolicy(
		`        - { id: mask-phones, when: 'finding.subtype == "phone"', action: redact }`)}})
	resp, _ := f.chat(t, f.key, "llama-70b", "+00000000+00000000")
	if resp.StatusCode != http.StatusInternalServerError || errorCode(t, resp) != "redaction_failed" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if d := lastDecision(t, f); d.ReasonCode != "REDACTION_FAILED" || rec.count() != 0 {
		t.Errorf("record = %s, backend calls %d", d.ReasonCode, rec.count())
	}
}

func TestRestrictDestinationsKeepsARequestHome(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, policies: []policy.Source{actionPolicy(
		`        - { id: emails-stay-home, when: 'finding.subtype == "email"', action: restrict_destinations }`)}})
	// without an e-mail the external provider (first in the route) is used
	if _, who := f.chat(t, f.key, "shared", "hello"); who != "partner-eu" {
		t.Fatalf("no finding: answered by %q", who)
	}
	resp, who := f.chat(t, f.key, "shared", "write to "+canaryEmail)
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || who != "local" || len(d.Candidates) != 2 || d.Candidates[0].Excluded != policy.ExcludedClass {
		t.Fatalf("status %d by %q candidates %+v", resp.StatusCode, who, d.Candidates)
	}
	if len(d.Constraints) != 1 || d.Constraints[0] != "internal" || d.Label != "internal" {
		t.Errorf("constraints %v label %s: the label is unchanged, only the destinations", d.Constraints, d.Label)
	}
	// an external-only model is refused for such a request
	if resp, _ := f.chat(t, f.key, "partner-only", "write to "+canaryEmail); resp.StatusCode != 403 || lastDecision(t, f).ReasonCode != "NO_ELIGIBLE_BACKEND" {
		t.Errorf("external-only model: status %d", resp.StatusCode)
	}
}

func TestFlagOnlyRecords(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, policies: []policy.Source{actionPolicy(
		`        - { id: watch-emails, when: 'finding.subtype == "email"', action: flag }`)}})
	resp, _ := f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || len(d.RulesMatched) != 1 || d.RulesMatched[0] != "acts/watch-emails" || d.Redactions != nil {
		t.Errorf("status %d record %v %v", resp.StatusCode, d.RulesMatched, d.Redactions)
	}
	if !strings.Contains(metricsText(t, f), `tavian_policy_actions_total{action="flag"} 1`) {
		t.Error("flag not counted")
	}
}

// Phase B holds the restriction made by an action, not only the table.
func TestPhaseBHonoursRestrictDestinations(t *testing.T) {
	faulty := faultyRouter()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, deps: faulty, policies: []policy.Source{actionPolicy(
		`        - { id: emails-stay-home, when: 'finding.subtype == "email"', action: restrict_destinations }`)}})
	resp, _ := f.chat(t, f.key, "shared", "write to "+canaryEmail)
	if resp.StatusCode != http.StatusInternalServerError || lastDecision(t, f).ReasonCode != "ROUTING_ASSERTION_FAILED" || f.partnerCalls.Load() != 0 {
		t.Fatalf("status %d, external calls %d", resp.StatusCode, f.partnerCalls.Load())
	}
}

func TestDecisionRecordOfARedactedRequestHoldsNoValue(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, policies: []policy.Source{actionPolicy(
		`        - { id: mask-emails, when: 'finding.subtype == "email"', action: redact }`)}})
	f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	raw, _ := json.Marshal(lastDecision(t, f))
	if strings.Contains(string(raw), "canary") {
		t.Errorf("record leaks the address: %s", raw)
	}
}

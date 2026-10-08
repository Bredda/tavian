package audit

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/inspect"
)

func TestReasonCatalogue(t *testing.T) {
	code := regexp.MustCompile(`^[A-Z][A-Z0-9_]*[A-Z0-9]$`)
	codes, clients := map[string]bool{}, map[string]bool{}
	for _, r := range All() {
		if !code.MatchString(r.Code) {
			t.Errorf("reason code %q: want UPPER_SNAKE_CASE", r.Code)
		}
		if codes[r.Code] {
			t.Errorf("reason code %q is used twice", r.Code)
		}
		codes[r.Code] = true
		if r.Client != "" {
			if clients[r.Client] {
				t.Errorf("client error code %q is used twice", r.Client)
			}
			clients[r.Client] = true
			if r.Status < 400 || r.Status > 599 || r.Type == "" {
				t.Errorf("%s: an error needs a 4xx/5xx status and a type, got %d %q", r.Code, r.Status, r.Type)
			}
		}
	}
	// the client codes SDK users already receive must not change
	for _, want := range []string{"invalid_request", "request_too_large", "model_not_allowed", "model_not_found",
		"multimodal_not_inspectable", "request_too_complex", "inspection_failed", "upstream_unavailable"} {
		if !clients[want] {
			t.Errorf("client error code %q disappeared from the catalogue", want)
		}
	}
}

func TestFromInspection(t *testing.T) {
	for code, want := range map[string]Reason{
		inspect.GapMultimodal: MultimodalNotInspected,
		inspect.GapTooComplex: RequestTooComplex,
		inspect.CodeFailed:    InspectionFailed,
		"something else":      InspectionFailed,
	} {
		if got := FromInspection(code); got != want {
			t.Errorf("FromInspection(%q) = %s, want %s", code, got.Code, want.Code)
		}
	}
	// the inspection package and the catalogue must agree on client codes
	if MultimodalNotInspected.Client != inspect.GapMultimodal || RequestTooComplex.Client != inspect.GapTooComplex || InspectionFailed.Client != inspect.CodeFailed {
		t.Error("client codes of inspection reasons drifted from internal/inspect")
	}
}

func finding(i int) inspect.Finding {
	return inspect.Finding{
		Detector: "pii.iban", Type: inspect.TypePII, Subtype: "iban", Severity: inspect.SeverityHigh, Confidence: 0.95,
		Location: inspect.Location{Segment: i, MessageIndex: i, Field: inspect.FieldContent, Part: -1, Start: 1, End: 30},
		// as left by the engine: fingerprint set, canonical value cleared
		Fingerprint: "0123456789abcdef0123456789abcdef",
	}
}

func TestWithInspectionCapsFindingsButNotCounts(t *testing.T) {
	res := inspect.Result{Status: inspect.StatusOK}
	for i := range MaxFindings + 50 {
		res.Findings = append(res.Findings, finding(i))
	}
	var d DecisionRecord
	d.WithInspection(res)
	if len(d.Findings) != MaxFindings || !d.FindingsTruncated {
		t.Errorf("findings = %d truncated = %v, want %d and truncated", len(d.Findings), d.FindingsTruncated, MaxFindings)
	}
	if d.Inspection == nil || d.Inspection.Findings != MaxFindings+50 || d.Inspection.Counts["pii.iban"] != MaxFindings+50 {
		t.Errorf("the summary must keep the complete counts: %+v", d.Inspection)
	}

	// even a full record stays far below what the spool can replay
	d.RequestID, d.Revision, d.Team, d.Application = strings.Repeat("r", 64), "0123456789ab", strings.Repeat("t", 63), strings.Repeat("a", 63)
	b, _ := json.Marshal(d)
	if len(b) > 256<<10 {
		t.Errorf("a record with the maximum of findings is %d bytes", len(b))
	}
}

func TestRecordCarriesNoValueAndTheEventContract(t *testing.T) {
	var d DecisionRecord
	d.DecisionID, d.Time = "dec-1", time.Unix(1_700_000_000, 0).UTC()
	d.Outcome, d.ReasonCode, d.Status = OutcomeRefused, ModelNotAllowed.Code, 403
	d.WithInspection(inspect.Result{Status: inspect.StatusOK, Findings: []inspect.Finding{finding(0)}})
	if d.Kind() != KindDecision || d.ID() != "dec-1" || !d.At().Equal(d.Time) {
		t.Errorf("event contract: %s %s %v", d.Kind(), d.ID(), d.At())
	}
	b, _ := json.Marshal(d)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"decision_id", "outcome", "reason_code", "status", "inspection", "findings"} {
		if _, ok := m[key]; !ok {
			t.Errorf("record lacks %q: %s", key, b)
		}
	}
	if strings.Contains(string(b), "canonical") {
		t.Errorf("the canonical value must never be serialized: %s", b)
	}
}

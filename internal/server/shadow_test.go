package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/policy"
)

func trial(mode, rest string) policy.Source {
	return policyFile("trial.yaml", `
metadata: { name: trial, mode: `+mode+` }
spec:
  scope: { organization: true }
`+rest)
}

// The same policy, in shadow mode and then enforced: the first records what it
// would have done and changes nothing, the second does it.
func TestShadowBlockIsRecordedNotEnforced(t *testing.T) {
	const rule = `  inspection: { request: { on_finding: [ { id: no-emails, when: 'finding.subtype == "email"', action: block, reason: NO_EMAILS } ] } }
`
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: rec, policies: []policy.Source{trial("shadow", rule)}})
	resp, _ := f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	if resp.StatusCode != 200 || rec.count() != 1 {
		t.Fatalf("shadow: status %d, backend calls %d: nothing may be enforced", resp.StatusCode, rec.count())
	}
	if !strings.Contains(rec.all(), canaryEmail) {
		t.Error("a shadow policy changed the request")
	}
	d := lastDecision(t, f)
	if d.Outcome != "served" || d.ReasonCode != "SERVED" || d.Shadow == nil || d.Shadow.WouldRefuse != "NO_EMAILS" ||
		len(d.Shadow.Policies) != 1 || d.Shadow.Policies[0] != "trial" || len(d.Shadow.RulesMatched) != 1 || d.Shadow.RulesMatched[0] != "trial/no-emails" {
		t.Errorf("record = %s/%s shadow %+v", d.Outcome, d.ReasonCode, d.Shadow)
	}
	if len(d.RulesMatched) != 0 {
		t.Errorf("a shadow rule is listed as enforced: %v", d.RulesMatched)
	}
	if !strings.Contains(metricsText(t, f), `tavian_policy_shadow_total{change="block"} 1`) {
		t.Error("shadow block not counted")
	}
	if strings.Contains(metricsText(t, f), `tavian_policy_actions_total{action="block"}`) {
		t.Error("a shadow block counted as an enforced action")
	}

	// the same policy enforced
	g := buildFixture(t, fixtureSpec{maxBody: 1 << 20, policies: []policy.Source{trial("enforce", rule)}})
	resp, _ = g.chat(t, g.key, "llama-70b", "write to "+canaryEmail)
	if resp.StatusCode != http.StatusForbidden || lastDecision(t, g).ReasonCode != "NO_EMAILS" || lastDecision(t, g).Shadow != nil {
		t.Errorf("enforced: status %d", resp.StatusCode)
	}
}

func TestShadowLabelShowsWhoWouldBeRefused(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, policies: []policy.Source{trial("shadow", `  classification: { default: restricted }
`)}})
	// research (default clearance) would exceed its clearance; finance (cleared
	// for confidential) would too, with a restricted default
	resp, who := f.chat(t, f.key, "shared", "hello")
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || who != "partner-eu" || d.Label != "internal" {
		t.Fatalf("status %d by %q label %s: the request must be served as if there were no shadow policy", resp.StatusCode, who, d.Label)
	}
	if d.Shadow == nil || d.Shadow.Label != "restricted" || !d.Shadow.ExceedsClearance || d.Shadow.Constraints == nil || len(*d.Shadow.Constraints) != 1 {
		t.Errorf("shadow = %+v", d.Shadow)
	}
	m := metricsText(t, f)
	for _, want := range []string{`tavian_policy_shadow_total{change="label"} 1`, `tavian_policy_shadow_total{change="clearance"} 1`, `tavian_policy_shadow_total{change="destinations"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, grepLines(m, "shadow"))
		}
	}
	// a key already cleared for restricted data would not be affected by the clearance
	resp, _ = f.chat(t, f.top, "shared", "hello")
	if d := lastDecision(t, f); resp.StatusCode != 200 || d.Shadow == nil || d.Shadow.ExceedsClearance {
		t.Errorf("restricted key: status %d shadow %+v", resp.StatusCode, d.Shadow)
	}
}

func TestShadowModelDenialAndRedaction(t *testing.T) {
	rec := newRecorder()
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: rec, policies: []policy.Source{trial("shadow", `  models: { deny: ["llama-*"] }
  inspection: { request: { on_finding: [ { id: mask, when: 'finding.subtype == "email"', action: redact } ] } }
`)}})
	resp, _ := f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || !strings.Contains(rec.all(), canaryEmail) {
		t.Fatalf("status %d: nothing may be enforced, and the backend must get the original", resp.StatusCode)
	}
	if d.Shadow == nil || d.Shadow.WouldDenyModel != "trial" || len(d.Shadow.WouldRedact) != 1 || d.Shadow.WouldRedact[0] != "pii.email" || d.Redactions != nil {
		t.Errorf("shadow = %+v redactions %v", d.Shadow, d.Redactions)
	}
	m := metricsText(t, f)
	if !strings.Contains(m, `tavian_policy_shadow_total{change="model"} 1`) || !strings.Contains(m, `tavian_policy_shadow_total{change="redact"} 1`) {
		t.Errorf("metrics:\n%s", grepLines(m, "shadow"))
	}
}

func TestBrokenShadowPolicyDoesNotFailTheRequest(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, policies: []policy.Source{trial("shadow", `  inspection: { request: { on_finding: [ { id: div, when: 'finding.count == 0 || 10 / (finding.count - 1) == 1', action: flag } ] } }
`)}})
	resp, _ := f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || d.Shadow == nil || !strings.Contains(d.Shadow.Error, "trial/div") {
		t.Errorf("status %d shadow %+v", resp.StatusCode, d.Shadow)
	}
	if !strings.Contains(metricsText(t, f), `tavian_policy_shadow_total{change="error"} 1`) {
		t.Error("shadow failure not counted")
	}
}

func TestNoShadowSectionWithoutShadowPolicies(t *testing.T) {
	f := newFixture(t, 0)
	f.chat(t, f.key, "llama-70b", "hello")
	if d := lastDecision(t, f); d.Shadow != nil {
		t.Errorf("shadow = %+v", d.Shadow)
	}
}

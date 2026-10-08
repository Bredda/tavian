package server

import (
	"net/http"
	"testing"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/router"
)

func policyFile(name, doc string) policy.Source {
	return policy.Source{Name: name, Raw: []byte("apiVersion: tavian/v1alpha1\nkind: Policy\n" + doc)}
}

func withPolicies(t *testing.T, external bool, files ...policy.Source) *fixture {
	t.Helper()
	return buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: external, policies: files})
}

// A team policy can take models away from the ones its keys grant.
func TestPolicyDeniesModelsForItsTeamOnly(t *testing.T) {
	f := withPolicies(t, false, policyFile("research.yaml", `
metadata: { name: research-limits }
spec:
  scope: { team: research }
  models: { deny: ["llama-70b"] }
`))
	// the key "dev" is in team research and is granted llama-*
	resp, _ := f.chat(t, f.key, "llama-70b", "hello")
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "model_not_allowed" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	d := lastDecision(t, f)
	if d.ReasonCode != "MODEL_NOT_ALLOWED" || len(d.RulesMatched) != 1 || d.RulesMatched[0] != "research-limits/models" {
		t.Errorf("record = %s %v", d.ReasonCode, d.RulesMatched)
	}
	if len(f.sink.Events()) != 0 || d.Inspection != nil {
		t.Error("a refused model must cost no inspection and produce no usage")
	}
	// the finance team is not affected
	if resp, _ := f.chat(t, f.conf, "llama-70b", "hello"); resp.StatusCode != 200 {
		t.Errorf("finance: status = %d", resp.StatusCode)
	}
}

func TestPolicyAllowListNarrowsWhatTheKeyGrants(t *testing.T) {
	f := withPolicies(t, false, policyFile("only-broken.yaml", `
metadata: { name: only-broken }
spec:
  scope: { application: demo }
  models: { allow: ["broken"] }
`))
	if resp, _ := f.chat(t, f.key, "llama-70b", "hello"); resp.StatusCode != 403 {
		t.Errorf("llama-70b: status = %d, want 403: the key grants it but the policy does not", resp.StatusCode)
	}
	if resp, _ := f.chat(t, f.key, "broken", "hello"); resp.StatusCode == 403 {
		t.Error("broken is in the policy's allow list")
	}
}

// Labels for what the built-in rules ignore: here a custom dictionary.
func TestPolicyRulesGiveLabelsToCustomDetectors(t *testing.T) {
	policies := []policy.Source{policyFile("codenames.yaml", `
metadata: { name: codenames }
spec:
  scope: { organization: true }
  classification:
    infer:
      - id: aurore
        when: finding.type == "custom" && finding.subtype == "codenames"
        label: confidential
`)}
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, policies: policies, snap: func(s *config.Snapshot) {
		e, err := inspect.New(inspect.Config{Dictionaries: []inspect.Dictionary{{Name: "codenames", Terms: []string{"Projet Aurore"}}}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.Inspector = e
	}})
	// a key with the default clearance cannot send it
	resp, _ := f.chat(t, f.key, "shared", "budget du Projet Aurore")
	if resp.StatusCode != 403 || errorCode(t, resp) != "classification_exceeds_clearance" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	d := lastDecision(t, f)
	if d.Label != "confidential" || d.LabelSources.Inferred != "confidential" || len(d.RulesMatched) != 1 || d.RulesMatched[0] != "codenames/aurore" {
		t.Errorf("record = %s %+v %v", d.Label, d.LabelSources, d.RulesMatched)
	}
	// a key cleared for confidential data can, and it stays on-prem
	resp, who := f.chat(t, f.conf, "shared", "budget du Projet Aurore")
	if resp.StatusCode != 200 || who != "local" || f.partnerCalls.Load() != 0 {
		t.Errorf("status = %d answered by %q, external calls %d", resp.StatusCode, who, f.partnerCalls.Load())
	}
	// ordinary text is unaffected
	if resp, who := f.chat(t, f.key, "shared", "bonjour"); resp.StatusCode != 200 || who != "partner-eu" {
		t.Errorf("ordinary: status = %d by %q", resp.StatusCode, who)
	}
}

func TestPolicyNarrowsDestinationsForATeam(t *testing.T) {
	f := withPolicies(t, true, policyFile("closed.yaml", `
metadata: { name: research-stays-home }
spec:
  scope: { team: research }
  destinations:
    internal: [internal]
`))
	// research: internal data may not go to the external provider any more
	resp, who := f.chat(t, f.key, "shared", "hello")
	if resp.StatusCode != 200 || who != "local" || f.partnerCalls.Load() != 0 {
		t.Fatalf("research: status %d by %q, external calls %d", resp.StatusCode, who, f.partnerCalls.Load())
	}
	d := lastDecision(t, f)
	if len(d.Constraints) != 1 || d.Constraints[0] != "internal" || len(d.Candidates) != 2 ||
		d.Candidates[0].Excluded != policy.ExcludedClass || d.Candidates[1].Excluded != "" {
		t.Errorf("constraints %v candidates %+v", d.Constraints, d.Candidates)
	}
	// and the external-only model is refused for them
	if resp, _ := f.chat(t, f.key, "partner-only", "hello"); resp.StatusCode != 403 || lastDecision(t, f).ReasonCode != "NO_ELIGIBLE_BACKEND" {
		t.Errorf("external-only model for research: %d", resp.StatusCode)
	}
	// finance (key conf) is not affected
	if _, who := f.chat(t, f.conf, "shared", "hello"); who != "partner-eu" {
		t.Errorf("finance answered by %q, want partner-eu", who)
	}
}

func TestPolicyDefaultLabelOfATeam(t *testing.T) {
	f := withPolicies(t, true, policyFile("finance.yaml", `
metadata: { name: finance-default }
spec:
  scope: { team: finance }
  classification: { default: confidential }
`))
	resp, who := f.chat(t, f.conf, "shared", "bonjour") // finance
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || who != "local" || d.Label != "confidential" || d.LabelSources.Default != "confidential" {
		t.Errorf("finance: status %d by %q label %s sources %+v", resp.StatusCode, who, d.Label, d.LabelSources)
	}
	// research keeps internal
	if _, who := f.chat(t, f.key, "shared", "bonjour"); who != "partner-eu" {
		t.Errorf("research answered by %q", who)
	}
	// a default above a key's clearance makes that key unusable, visibly
	g := withPolicies(t, true, policyFile("all.yaml", `
metadata: { name: everything-restricted }
spec:
  scope: { organization: true }
  classification: { default: restricted }
`))
	if resp, _ := g.chat(t, g.conf, "shared", "bonjour"); resp.StatusCode != 403 || lastDecision(t, g).ReasonCode != "CLEARANCE_EXCEEDED" {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestRuleThatCannotBeEvaluatedFailsTheRequestClosed(t *testing.T) {
	f := withPolicies(t, false, policyFile("fragile.yaml", `
metadata: { name: fragile }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: div, when: 'finding.count == 0 || 10 / (finding.count - 1) == 1', label: restricted }
`))
	// no finding: nothing to evaluate
	if resp, _ := f.chat(t, f.key, "llama-70b", "hello"); resp.StatusCode != 200 {
		t.Fatalf("no finding: status = %d", resp.StatusCode)
	}
	// one e-mail: count 1 divides by zero
	resp, _ := f.chat(t, f.key, "llama-70b", "write to "+canaryEmail)
	if resp.StatusCode != http.StatusInternalServerError || errorCode(t, resp) != "policy_error" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	d := lastDecision(t, f)
	if d.ReasonCode != "POLICY_ERROR" || d.Outcome != audit.OutcomeRefused {
		t.Errorf("record = %s %s", d.ReasonCode, d.Outcome)
	}
}

// Phase B evaluates the policies again, so a router that ignores the
// constraints is caught by a team policy as well as by the baseline.
func TestPhaseBHonoursTeamPolicies(t *testing.T) {
	faulty := func(d *Deps) {
		d.Route = func(s *config.Snapshot, model string, _ policy.Constraints) (router.Route, []router.Candidate, error) {
			m := s.Models[model]
			return router.Route{Backend: s.Backends[m.Route[0].Backend], UpstreamModel: m.Route[0].UpstreamModel}, nil, nil
		}
	}
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, deps: []func(*Deps){faulty}, policies: []policy.Source{policyFile("closed.yaml", `
metadata: { name: research-stays-home }
spec:
  scope: { team: research }
  destinations:
    internal: [internal]
`)}})
	// internal data would be allowed externally by the baseline: only the team
	// policy forbids it
	resp, _ := f.chat(t, f.key, "shared", "hello")
	if resp.StatusCode != http.StatusInternalServerError || lastDecision(t, f).ReasonCode != "ROUTING_ASSERTION_FAILED" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if f.partnerCalls.Load() != 0 {
		t.Fatal("the external backend was called against the team policy")
	}
}

func TestRequestFieldsAreVisibleToRules(t *testing.T) {
	f := withPolicies(t, false, policyFile("tools.yaml", `
metadata: { name: tools }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: tools-with-emails, when: 'request.has_tools && finding.subtype == "email"', label: restricted }
      - { id: big-streams, when: 'request.stream && request.max_tokens > 1000 && finding.subtype == "email"', label: confidential }
`))
	email := "write to " + canaryEmail
	plain := `{"model":"llama-70b","messages":[{"role":"user","content":"` + email + `"}]`
	for body, want := range map[string]int{
		plain + `}`: 200,
		plain + `,"tools":[{"type":"function","function":{"name":"f"}}]}`: 403,
		plain + `,"stream":true,"max_tokens":50}`:                         200,
		plain + `,"stream":true,"max_tokens":5000}`:                       403,
		plain + `,"max_tokens":5000}`:                                     200,
	} {
		resp := f.post(t, f.key, body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status = %d, want %d", body[len(plain):], resp.StatusCode, want)
		}
	}
}

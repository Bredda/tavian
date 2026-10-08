package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/router"
)

func externalFixture(t *testing.T, opts ...func(*Deps)) *fixture {
	t.Helper()
	return buildFixture(t, fixtureSpec{maxBody: 1 << 20, external: true, deps: opts})
}

func (f *fixture) chat(t *testing.T, key, model, content string) (*http.Response, string) {
	t.Helper()
	body := `{"model":"` + model + `","messages":[{"role":"user","content":"` + content + `"}]}`
	resp := f.post(t, key, body)
	var out struct {
		Backend string `json:"x_mock_backend"`
	}
	if resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &out)
	}
	return resp, out.Backend
}

// The scenario of docs/VISION.md, in the gateway: the same model name is served
// by an external provider and by the on-prem backend; data that must stay
// inside the organization goes to the on-prem one even though the external one
// comes first in the route.
func TestSensitiveDataStaysOnPremEvenWhenTheRoutePrefersExternal(t *testing.T) {
	f := externalFixture(t)

	// ordinary data follows the route: external first
	resp, who := f.chat(t, f.key, "shared", "hello there")
	if resp.StatusCode != 200 || who != "partner-eu" {
		t.Fatalf("internal data: status %d answered by %q, want partner-eu", resp.StatusCode, who)
	}
	d := lastDecision(t, f)
	if d.Backend != "partner" || len(d.Candidates) != 1 || d.Candidates[0].Excluded != "" {
		t.Errorf("record = backend %q candidates %+v", d.Backend, d.Candidates)
	}

	// an IBAN makes it confidential: the on-prem backend answers
	before := f.partnerCalls.Load()
	resp, who = f.chat(t, f.conf, "shared", "pay "+canaryIBAN)
	if resp.StatusCode != 200 || who != "local" {
		t.Fatalf("confidential data: status %d answered by %q, want local", resp.StatusCode, who)
	}
	if f.partnerCalls.Load() != before {
		t.Error("the external backend received a request carrying an IBAN")
	}
	d = lastDecision(t, f)
	want := []audit.Candidate{{Backend: "partner", Excluded: policy.ExcludedClearance}, {Backend: "local"}}
	if d.Backend != "local" || d.UpstreamModel != "mock-local" || d.Label != "confidential" || len(d.Candidates) != 2 || d.Candidates[0] != want[0] || d.Candidates[1] != want[1] {
		t.Errorf("record = backend %q upstream %q label %q candidates %+v", d.Backend, d.UpstreamModel, d.Label, d.Candidates)
	}
	ev := f.sink.Events()
	if last := ev[len(ev)-1]; last.Backend != "local" || last.Label != "confidential" {
		t.Errorf("usage event = %+v", last)
	}

	// a declared label alone is enough, without anything detectable
	resp, who = f.postDeclared(t, f.conf, "shared", "nothing special", "confidential")
	if resp.StatusCode != 200 || who != "local" {
		t.Errorf("declared confidential: status %d answered by %q", resp.StatusCode, who)
	}
}

func (f *fixture) postDeclared(t *testing.T, key, model, content, label string) (*http.Response, string) {
	t.Helper()
	resp := f.postWithLabel(t, key, `{"model":"`+model+`","messages":[{"role":"user","content":"`+content+`"}]}`, label)
	var out struct {
		Backend string `json:"x_mock_backend"`
	}
	if resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &out)
	}
	return resp, out.Backend
}

// ...and a model that only exists externally is refused for such data, with a
// reason the caller and the auditor can read.
func TestExternalOnlyModelIsRefusedForSensitiveData(t *testing.T) {
	f := externalFixture(t)

	resp, who := f.chat(t, f.key, "partner-only", "hello there")
	if resp.StatusCode != 200 || who != "partner-eu" {
		t.Fatalf("ordinary data: status %d by %q", resp.StatusCode, who)
	}

	before := f.partnerCalls.Load()
	resp, _ = f.chat(t, f.conf, "partner-only", "pay "+canaryIBAN)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "no_eligible_backend" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if f.partnerCalls.Load() != before {
		t.Error("the external backend was called for a request that must not reach it")
	}
	d := lastDecision(t, f)
	if d.Outcome != audit.OutcomeRefused || d.ReasonCode != "NO_ELIGIBLE_BACKEND" || d.Label != "confidential" || d.Backend != "" ||
		len(d.Candidates) != 1 || d.Candidates[0].Backend != "partner" || d.Candidates[0].Excluded != policy.ExcludedClearance {
		t.Errorf("record = %+v", d)
	}
	if n := len(f.sink.Events()); n != 1 {
		t.Errorf("usage events = %d: only the first, served request used a backend", n)
	}
	if !strings.Contains(metricsText(t, f), `tavian_requests_total{outcome="no_eligible_backend",route="chat_completions"} 1`) {
		t.Error("outcome not counted")
	}
}

func TestRestrictedDataNeverLeavesEvenWhenTheBackendIsTrusted(t *testing.T) {
	f := externalFixture(t)
	resp, who := f.chat(t, f.top, "shared", "key "+canarySec)
	if resp.StatusCode != 200 || who != "local" {
		t.Errorf("restricted data: status %d by %q, want local", resp.StatusCode, who)
	}
	if f.partnerCalls.Load() != 0 {
		t.Error("restricted data reached the external backend")
	}
}

// Phase B: a router that ignores the constraints must not be able to send data
// where it must not go.
func TestPhaseBCatchesAFaultyRouter(t *testing.T) {
	faulty := func(d *Deps) {
		d.Route = func(s *config.Snapshot, model string, _ policy.Constraints) (router.Route, []router.Candidate, error) {
			// first target of the model, constraints ignored
			m := s.Models[model]
			if m == nil || len(m.Route) == 0 {
				return router.Route{}, nil, router.ErrUnknownModel
			}
			return router.Route{Backend: s.Backends[m.Route[0].Backend], UpstreamModel: m.Route[0].UpstreamModel}, nil, nil
		}
	}
	f := externalFixture(t, faulty)
	resp, _ := f.chat(t, f.conf, "shared", "pay "+canaryIBAN)
	if resp.StatusCode != http.StatusInternalServerError || errorCode(t, resp) != "internal_error" {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if f.partnerCalls.Load() != 0 {
		t.Fatal("the faulty router sent an IBAN to the external backend: phase B did not stop it")
	}
	d := lastDecision(t, f)
	if d.Outcome != audit.OutcomeRefused || d.ReasonCode != "ROUTING_ASSERTION_FAILED" || d.Label != "confidential" {
		t.Errorf("record = %+v", d)
	}
	if n := len(f.sink.Events()); n != 0 {
		t.Errorf("usage events = %d", n)
	}
}

func TestRouterErrorsAreRefusalsNotPanics(t *testing.T) {
	boom := func(d *Deps) {
		d.Route = func(*config.Snapshot, string, policy.Constraints) (router.Route, []router.Candidate, error) {
			return router.Route{}, nil, errors.New("boom")
		}
	}
	f := externalFixture(t, boom)
	resp, _ := f.chat(t, f.key, "shared", "hello")
	if resp.StatusCode != http.StatusInternalServerError || lastDecision(t, f).ReasonCode != "ROUTING_ASSERTION_FAILED" {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

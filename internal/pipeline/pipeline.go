// Package pipeline is the decision part of the request lifecycle
// (docs/ARCHITECTURE.md §4): authorize the model, apply the policies to what
// inspection found, check the clearance, route, and assert the route. It does
// no I/O, so the gateway and `tavian policy test` run exactly the same code and
// cannot disagree about what a policy does.
package pipeline

import (
	"errors"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/glob"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/router"
	"github.com/bredda/tavian/internal/taxonomy"
)

// Caller is who sends the request: the identity policies see, and what the
// caller's credentials grant.
type Caller struct {
	policy.Identity
	// Grants are the model patterns the credentials allow.
	Grants []string
	// Clearance is the most sensitive label the caller may send.
	Clearance taxonomy.Label
}

// Refusal says why a request is not served, in the terms the client and the
// audit trail need.
type Refusal struct {
	Reason  audit.Reason
	Message string
	// Outcome is the short label counted in the request metrics.
	Outcome string
	// Matched are the policies and rules to add to the decision record.
	Matched []string
}

// AuthorizeModel checks that the credentials grant the model and that so do
// the policies. It looks only at the caller and the model, so a refused model
// costs no inspection time. It returns nil when the model is allowed, and in
// shadow mode the policies that would have denied it.
func AuthorizeModel(snap *config.Snapshot, c Caller, model string) (*Refusal, *policy.ShadowModel) {
	deny := func(matched ...string) *Refusal {
		return &Refusal{Reason: audit.ModelNotAllowed, Message: "you may not use the requested model", Outcome: "denied_model", Matched: matched}
	}
	if !glob.MatchAny(c.Grants, model) {
		return deny(), nil
	}
	v := snap.Policy.AuthorizeModel(c.Identity, model)
	if !v.Allowed {
		return deny(v.Policy + "/models"), nil
	}
	return nil, v.Shadow
}

// RouteFunc picks the backend for a model under the constraints; it is
// router.Resolve, replaceable in tests to prove that phase B catches a faulty
// router.
type RouteFunc func(*config.Snapshot, string, policy.Constraints) (router.Route, []router.Candidate, error)

// Result is the outcome of Evaluate.
type Result struct {
	// Decision is valid when Decided is true (the policies could be evaluated).
	Decision   policy.Decision
	Decided    bool
	Route      router.Route
	Candidates []router.Candidate
	// Refusal is set when the request must not be served.
	Refusal *Refusal
	// Err is the internal error behind a refusal, for the logs. It never
	// reaches the client.
	Err error
}

// Evaluate applies phase A of the policies to what inspection found, refuses a
// blocked request or one above the caller's clearance, routes among the
// backends the constraints allow, and asserts the choice (phase B).
func Evaluate(snap *config.Snapshot, route RouteFunc, c Caller, in policy.Input) Result {
	if route == nil {
		route = router.Resolve
	}
	var res Result

	decision, err := snap.Policy.Decide(in)
	if err != nil {
		res.Err = err
		res.Refusal = &Refusal{Reason: audit.PolicyError, Message: "the request could not be evaluated against the policies", Outcome: "policy_error"}
		return res
	}
	res.Decision, res.Decided = decision, true
	if sh := decision.Shadow; sh != nil && sh.Label != "" &&
		sh.Label.Rank() > c.Clearance.Rank() && decision.Label.Rank() <= c.Clearance.Rank() {
		sh.ExceedsClearance = true
	}

	if decision.Block != nil {
		reason := audit.PolicyBlocked
		reason.Code = decision.Block.Reason // the rule's own code, for the record
		res.Refusal = &Refusal{Reason: reason, Message: "the request was blocked by policy (" + decision.Block.Reason + ")", Outcome: "policy_blocked"}
		return res
	}
	if decision.Label.Rank() > c.Clearance.Rank() {
		res.Refusal = &Refusal{
			Reason: audit.ClearanceExceeded, Outcome: "clearance_exceeded",
			Message: "this request is classified " + string(decision.Label) + ", above the " + string(c.Clearance) + " your credentials are cleared to send",
		}
		return res
	}

	picked, candidates, err := route(snap, in.Request.Model, decision.Constraints)
	res.Candidates = candidates
	switch {
	case errors.Is(err, router.ErrUnknownModel):
		res.Refusal = &Refusal{Reason: audit.ModelNotFound, Message: "the requested model does not exist", Outcome: "model_not_found"}
		return res
	case errors.Is(err, router.ErrNoEligibleBackend):
		res.Refusal = &Refusal{
			Reason: audit.NoEligibleBackend, Outcome: "no_eligible_backend",
			Message: "no backend serving this model may receive a request classified " + string(decision.Label),
		}
		return res
	case err != nil:
		res.Err = err
		res.Refusal = &Refusal{Reason: audit.RoutingAssertion, Message: "internal error", Outcome: "routing_error"}
		return res
	}
	res.Route = picked

	// phase B: defence in depth, the chosen backend must satisfy the policies
	// whatever routing did
	b := picked.Backend
	if err := snap.Policy.Assert(c.Identity, decision, policy.Backend{ID: b.ID, Class: b.DestinationClass, Max: b.MaxClassification}); err != nil {
		res.Err = err
		res.Refusal = &Refusal{Reason: audit.RoutingAssertion, Message: "internal error", Outcome: "routing_assertion_failed"}
	}
	return res
}

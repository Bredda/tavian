// Package router resolves a requested model to a concrete backend. It picks the
// first target of the model's route that the constraints of the request allow;
// strategies, health and failover (always within allowed candidates) arrive in
// M3.
package router

import (
	"errors"

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/cost"
	"github.com/bredda/tavian/internal/policy"
)

// ErrUnknownModel means no model with that name is configured.
var ErrUnknownModel = errors.New("unknown model")

// ErrNoEligibleBackend means the model exists but none of its backends may
// receive the request under the constraints.
var ErrNoEligibleBackend = errors.New("no backend may receive this request")

// Route is the outcome of routing.
type Route struct {
	Backend       *config.Backend
	UpstreamModel string
	// Price and Energy are those of the target taken; nil if not configured.
	Price  *cost.Price
	Energy *cost.Energy
}

// Candidate records one backend that was considered, and why it was set aside
// ("" for the one that was chosen).
type Candidate struct {
	Backend  string
	Excluded string
}

// Resolve picks the backend for model in snapshot s. Targets are tried in the
// order of the model's route; it also returns the candidates looked at, which
// on failure are all the targets and say why none fit.
func Resolve(s *config.Snapshot, model string, c policy.Constraints) (Route, []Candidate, error) {
	m, ok := s.Models[model]
	if !ok || len(m.Route) == 0 {
		return Route{}, nil, ErrUnknownModel
	}
	var seen []Candidate
	for _, t := range m.Route {
		b, ok := s.Backends[t.Backend]
		if !ok {
			// Compile guarantees this cannot happen; refuse rather than guess.
			return Route{}, nil, ErrUnknownModel
		}
		if why := c.Excludes(b.DestinationClass, b.MaxClassification); why != "" {
			seen = append(seen, Candidate{Backend: b.ID, Excluded: why})
			continue
		}
		seen = append(seen, Candidate{Backend: b.ID})
		return Route{Backend: b, UpstreamModel: t.UpstreamModel, Price: t.Price, Energy: t.Energy}, seen, nil
	}
	return Route{}, seen, ErrNoEligibleBackend
}

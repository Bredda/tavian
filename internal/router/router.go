// Package router resolves a requested model to a concrete backend. M1 picks the
// first target of the model's route; strategies, health and failover (always
// within policy-allowed candidates) arrive in M3.
package router

import (
	"errors"

	"github.com/bredda/tavian/internal/config"
)

// ErrUnknownModel means no model with that name is configured.
var ErrUnknownModel = errors.New("unknown model")

// Route is the outcome of routing.
type Route struct {
	Backend       *config.Backend
	UpstreamModel string
}

// Resolve picks the backend for model in snapshot s.
func Resolve(s *config.Snapshot, model string) (Route, error) {
	m, ok := s.Models[model]
	if !ok || len(m.Route) == 0 {
		return Route{}, ErrUnknownModel
	}
	t := m.Route[0]
	b, ok := s.Backends[t.Backend]
	if !ok {
		// Compile guarantees this cannot happen; refuse rather than guess.
		return Route{}, ErrUnknownModel
	}
	return Route{Backend: b, UpstreamModel: t.UpstreamModel}, nil
}

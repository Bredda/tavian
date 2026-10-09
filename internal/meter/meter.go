// Package meter defines the usage event and where it goes (ADR-0009, ADR-0010).
//
// The event has its final multi-dimensional shape from M1: money, energy and
// carbon are nil until pricing and energy profiles exist, but adding them later
// will not need a schema change or a history rewrite.
package meter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/bredda/tavian/internal/cost"
	"github.com/bredda/tavian/internal/inspect"
)

// UsageEvent describes one served request. It never carries prompt or response
// content.
type UsageEvent struct {
	EventID   string `json:"event_id"`
	RequestID string `json:"request_id"`
	// DecisionID is the decision record of the same request.
	DecisionID string    `json:"decision_id,omitempty"`
	Time       time.Time `json:"time"`
	Revision   string    `json:"config_revision"`

	// Who: an API key, or a person/service account known to the identity
	// provider (subject), never both.
	AuthMethod  string `json:"auth_method"`
	KeyID       string `json:"key_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Team        string `json:"team"`
	Application string `json:"application"`

	// Label is the classification of the request.
	Label string `json:"label,omitempty"`

	Model         string `json:"model"`
	UpstreamModel string `json:"upstream_model"`
	Backend       string `json:"backend"`

	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	CachedTokens    int64 `json:"cached_tokens"`
	ReasoningTokens int64 `json:"reasoning_tokens"`
	// UsageKnown is false when the backend did not report token counts.
	UsageKnown bool `json:"usage_known"`

	// Nil until prices / energy profiles / carbon intensity are configured.
	// Money is in micro-euros to avoid floating-point rounding.
	CostMicroEUR *int64   `json:"cost_micro_eur,omitempty"`
	EnergyWh     *float64 `json:"energy_wh,omitempty"`
	CO2eGrams    *float64 `json:"co2e_g,omitempty"`
	// Basis is what those figures were computed from: prices, energy factors,
	// carbon intensity. Energy and carbon are estimates.
	Basis *cost.Basis `json:"cost_basis,omitempty"`

	// Inspection summarises what content inspection found: counts and detector
	// versions, never content or fingerprints. Nil only for events written
	// before inspection existed.
	Inspection *inspect.Summary `json:"inspection,omitempty"`

	Streamed  bool   `json:"streamed"`
	Status    int    `json:"status"`
	Outcome   string `json:"outcome"` // ok | upstream_error | stream_error | client_gone
	LatencyMS int64  `json:"latency_ms"`
	TTFBMS    int64  `json:"ttfb_ms"`
}

// Event is something the gateway records: a usage event, a decision record.
// It carries its own identity so sinks can store it without knowing its type.
type Event interface {
	// Kind names the type of event (the outbox kind).
	Kind() string
	// ID is unique per event; storing the same ID twice is harmless.
	ID() string
	// At is when the event happened.
	At() time.Time
}

// Kind, ID and At make a UsageEvent an Event.
func (UsageEvent) Kind() string    { return KindUsage }
func (e UsageEvent) ID() string    { return e.EventID }
func (e UsageEvent) At() time.Time { return e.Time }

// Sink receives events. A failing sink must be treated as an audit failure.
type Sink interface {
	Emit(ctx context.Context, e Event) error
}

// LogSink writes events as structured log records.
type LogSink struct{ Log *slog.Logger }

func (s LogSink) Emit(ctx context.Context, e Event) error {
	s.Log.LogAttrs(ctx, slog.LevelInfo, e.Kind(), slog.Any("event", e))
	return nil
}

// MemorySink keeps events in memory. Intended for tests.
type MemorySink struct {
	mu     sync.Mutex
	events []Event
}

func (s *MemorySink) Emit(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Records returns a copy of everything recorded, of every kind.
func (s *MemorySink) Records() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// Events returns a copy of the recorded usage events.
func (s *MemorySink) Events() []UsageEvent {
	var out []UsageEvent
	for _, e := range s.Records() {
		if u, ok := e.(UsageEvent); ok {
			out = append(out, u)
		}
	}
	return out
}

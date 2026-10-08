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
)

// UsageEvent describes one served request. It never carries prompt or response
// content.
type UsageEvent struct {
	EventID   string    `json:"event_id"`
	RequestID string    `json:"request_id"`
	Time      time.Time `json:"time"`
	Revision  string    `json:"config_revision"`

	// Who: an API key, or a person/service account known to the identity
	// provider (subject), never both.
	AuthMethod  string `json:"auth_method"`
	KeyID       string `json:"key_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Team        string `json:"team"`
	Application string `json:"application"`

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

	Streamed  bool   `json:"streamed"`
	Status    int    `json:"status"`
	Outcome   string `json:"outcome"` // ok | upstream_error | stream_error | client_gone
	LatencyMS int64  `json:"latency_ms"`
	TTFBMS    int64  `json:"ttfb_ms"`
}

// Sink receives usage events. The PostgreSQL outbox implementation arrives in
// M1's storage work; a failing sink must be treated as an audit failure.
type Sink interface {
	Emit(ctx context.Context, e UsageEvent) error
}

// LogSink writes events as structured log records.
type LogSink struct{ Log *slog.Logger }

func (s LogSink) Emit(ctx context.Context, e UsageEvent) error {
	s.Log.LogAttrs(ctx, slog.LevelInfo, "usage", slog.Any("event", e))
	return nil
}

// MemorySink keeps events in memory. Intended for tests.
type MemorySink struct {
	mu     sync.Mutex
	events []UsageEvent
}

func (s *MemorySink) Emit(_ context.Context, e UsageEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (s *MemorySink) Events() []UsageEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]UsageEvent(nil), s.events...)
}

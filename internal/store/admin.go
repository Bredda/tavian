package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// KindAdminChange is the outbox kind of an AdminChange. The audit chain covers
// it like a decision record; the retention pruner never removes it.
const KindAdminChange = "admin_change"

// Outcomes of an administration call.
const (
	OutcomeApplied  = "applied"  // the change is in effect
	OutcomeRejected = "rejected" // refused (invalid, conflicting); nothing changed
)

// AdminChange is the record of one administration call that changes, or tries
// to change, something. It is also the payload of the outbox event the audit
// chain covers, so every field is part of what the chain protects.
type AdminChange struct {
	EventID    string          `json:"event_id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Actor      string          `json:"actor"`  // the id of the admin token, or "sighup"
	Action     string          `json:"action"` // for example "config.reload"
	Target     string          `json:"target,omitempty"`
	Outcome    string          `json:"outcome"`
	RequestID  string          `json:"request_id,omitempty"`
	RemoteAddr string          `json:"remote_addr,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

// RecordAdminChange writes the change and its outbox event in one
// transaction: either both are there or neither is. Recording the same event
// twice is a no-op.
func (s *Store) RecordAdminChange(ctx context.Context, c AdminChange) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("record admin change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := recordAdminChange(ctx, tx, c); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("record admin change: %w", err)
	}
	return nil
}

// recordAdminChange writes the row and the outbox event within tx.
func recordAdminChange(ctx context.Context, tx pgx.Tx, c AdminChange) error {
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode admin change: %w", err)
	}
	detail := c.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO admin_changes (event_id, occurred_at, actor, action, target, outcome, request_id, remote_addr, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) ON CONFLICT (event_id) DO NOTHING`,
		c.EventID, c.OccurredAt, c.Actor, c.Action, c.Target, c.Outcome, c.RequestID, c.RemoteAddr, string(detail)); err != nil {
		return fmt.Errorf("record admin change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO outbox (event_id, kind, occurred_at, payload) VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING`,
		c.EventID, KindAdminChange, c.OccurredAt, payload); err != nil {
		return fmt.Errorf("record admin change: %w", err)
	}
	return nil
}

// ListAdminChanges returns the most recent changes, newest first. before, when
// positive, is the sequence number to continue from (exclusive); the returned
// next is the value to pass for the following page, 0 when there is none.
func (s *Store) ListAdminChanges(ctx context.Context, limit int, before int64) (changes []AdminChange, next int64, err error) {
	limit = min(max(limit, 1), 500)
	if before <= 0 {
		before = 1<<63 - 1
	}
	rs, err := s.pool.Query(ctx, `
SELECT seq, event_id, occurred_at, actor, action, target, outcome, request_id, remote_addr, detail::text
FROM admin_changes WHERE seq < $1 ORDER BY seq DESC LIMIT $2`, before, limit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("list admin changes: %w", err)
	}
	defer rs.Close()
	var seqs []int64
	for rs.Next() {
		var (
			c      AdminChange
			seq    int64
			detail string
		)
		if err := rs.Scan(&seq, &c.EventID, &c.OccurredAt, &c.Actor, &c.Action, &c.Target, &c.Outcome, &c.RequestID, &c.RemoteAddr, &detail); err != nil {
			return nil, 0, fmt.Errorf("list admin changes: %w", err)
		}
		c.Detail = json.RawMessage(detail)
		changes, seqs = append(changes, c), append(seqs, seq)
	}
	if err := rs.Err(); err != nil {
		return nil, 0, fmt.Errorf("list admin changes: %w", err)
	}
	if len(changes) > limit {
		changes, next = changes[:limit], seqs[limit-1]
	}
	return changes, next, nil
}

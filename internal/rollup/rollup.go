// Package rollup sums usage events by the hour, so that usage totals outlive the
// raw events (outbox retention) and quota counters can be rebuilt after a
// restart.
package rollup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/quota"
)

// ConsumerName is the name of the cursor of the rollup in outbox_consumers.
const ConsumerName = "usage-rollup"

// KindUsage is the outbox kind that is summed.
const KindUsage = "usage"

type key struct {
	hour                                         time.Time
	team, application, principal, model, backend string
	outcome                                      string
}

type sums struct {
	requests, unknown                int64
	input, output, cached, reasoning int64
	cost                             int64
	hasCost                          bool
}

// usageEvent is the part of a usage event the rollup reads.
type usageEvent struct {
	Time            time.Time `json:"time"`
	KeyID           string    `json:"key_id"`
	UserID          string    `json:"user_id"`
	Team            string    `json:"team"`
	Application     string    `json:"application"`
	Model           string    `json:"model"`
	Backend         string    `json:"backend"`
	Outcome         string    `json:"outcome"`
	InputTokens     int64     `json:"input_tokens"`
	OutputTokens    int64     `json:"output_tokens"`
	CachedTokens    int64     `json:"cached_tokens"`
	ReasoningTokens int64     `json:"reasoning_tokens"`
	UsageKnown      bool      `json:"usage_known"`
	CostMicroEUR    *int64    `json:"cost_micro_eur"`
}

// Consumer is the outbox consumer that maintains usage_hourly.
type Consumer struct {
	Log *slog.Logger
}

func (Consumer) Name() string    { return ConsumerName }
func (Consumer) Kinds() []string { return []string{KindUsage} }

// Handle adds a batch to the hourly sums. An event that cannot be read is
// logged (by id, never by content) and skipped: one malformed event must not
// stop the totals for everyone.
func (c Consumer) Handle(ctx context.Context, tx pgx.Tx, batch []outbox.Row) error {
	if len(batch) == 0 {
		return nil
	}
	acc := map[key]*sums{}
	for _, r := range batch {
		var e usageEvent
		if err := json.Unmarshal(r.Payload, &e); err != nil || e.Time.IsZero() {
			if c.Log != nil {
				c.Log.Error("usage event skipped by the rollup: unreadable", "event_id", r.EventID)
			}
			continue
		}
		principal := e.KeyID
		if principal == "" {
			principal = e.UserID
		}
		k := key{e.Time.UTC().Truncate(time.Hour), e.Team, e.Application, principal, e.Model, e.Backend, e.Outcome}
		s := acc[k]
		if s == nil {
			s = &sums{}
			acc[k] = s
		}
		s.requests++
		if !e.UsageKnown {
			s.unknown++
		}
		s.input += e.InputTokens
		s.output += e.OutputTokens
		s.cached += e.CachedTokens
		s.reasoning += e.ReasoningTokens
		if e.CostMicroEUR != nil {
			s.cost += *e.CostMicroEUR
			s.hasCost = true
		}
	}
	b := &pgx.Batch{}
	for k, s := range acc {
		var cost *int64
		if s.hasCost {
			cost = &s.cost
		}
		b.Queue(`
INSERT INTO usage_hourly (hour, team, application, principal, model, backend, outcome,
                          requests, usage_unknown, input_tokens, output_tokens, cached_tokens, reasoning_tokens, cost_micro_eur)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (hour, team, application, principal, model, backend, outcome) DO UPDATE SET
    requests         = usage_hourly.requests + EXCLUDED.requests,
    usage_unknown    = usage_hourly.usage_unknown + EXCLUDED.usage_unknown,
    input_tokens     = usage_hourly.input_tokens + EXCLUDED.input_tokens,
    output_tokens    = usage_hourly.output_tokens + EXCLUDED.output_tokens,
    cached_tokens    = usage_hourly.cached_tokens + EXCLUDED.cached_tokens,
    reasoning_tokens = usage_hourly.reasoning_tokens + EXCLUDED.reasoning_tokens,
    cost_micro_eur   = CASE WHEN usage_hourly.cost_micro_eur IS NULL AND EXCLUDED.cost_micro_eur IS NULL THEN NULL
                            ELSE COALESCE(usage_hourly.cost_micro_eur, 0) + COALESCE(EXCLUDED.cost_micro_eur, 0) END`,
			k.hour, k.team, k.application, k.principal, k.model, k.backend, k.outcome,
			s.requests, s.unknown, s.input, s.output, s.cached, s.reasoning, cost)
	}
	res := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return fmt.Errorf("rollup: %w", err)
		}
	}
	if err := res.Close(); err != nil {
		return fmt.Errorf("rollup: %w", err)
	}
	return nil
}

// TeamApp is the tokens one team and application used.
type TeamApp struct {
	Team, Application string
	Tokens            int64
}

// TokensToday returns the tokens (input plus output) used since 00:00 UTC of
// the day of now, by team and application: the hourly sums, plus the usage
// events the rollup has not reached yet. One statement, so the two halves come
// from one snapshot and no event is counted twice or missed.
func TokensToday(ctx context.Context, pool *pgxpool.Pool, now time.Time) ([]TeamApp, error) {
	n := now.UTC()
	dayStart := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	rs, err := pool.Query(ctx, `
WITH cur AS (
    SELECT COALESCE((SELECT last_xid FROM outbox_consumers WHERE name = $2), 0) AS xid,
           COALESCE((SELECT last_seq FROM outbox_consumers WHERE name = $2), 0) AS seq
), rolled AS (
    SELECT team, application, sum(input_tokens + output_tokens) AS tokens
    FROM usage_hourly WHERE hour >= $1 GROUP BY team, application
), tail AS (
    SELECT o.payload->>'team' AS team, o.payload->>'application' AS application,
           sum(COALESCE((o.payload->>'input_tokens')::bigint, 0) + COALESCE((o.payload->>'output_tokens')::bigint, 0)) AS tokens
    FROM outbox o, cur
    WHERE o.kind = $3 AND (o.xid, o.seq) > (cur.xid::text::xid8, cur.seq)
      AND (o.payload->>'time')::timestamptz >= $1
    GROUP BY 1, 2
)
SELECT team, application, sum(tokens)::bigint
FROM (SELECT * FROM rolled UNION ALL SELECT * FROM tail) u
GROUP BY team, application`, dayStart, ConsumerName, KindUsage)
	if err != nil {
		return nil, fmt.Errorf("tokens used today: %w", err)
	}
	defer rs.Close()
	var out []TeamApp
	for rs.Next() {
		var t TeamApp
		var team, app *string
		if err := rs.Scan(&team, &app, &t.Tokens); err != nil {
			return nil, fmt.Errorf("tokens used today: %w", err)
		}
		if team != nil {
			t.Team = *team
		}
		if app != nil {
			t.Application = *app
		}
		out = append(out, t)
	}
	return out, rs.Err()
}

// Seed gives the daily token counters of store the usage already recorded
// today, for the scopes that have a daily limit. A counter that exists is left
// alone: it knows better. It returns how many counters it set.
func Seed(ctx context.Context, pool *pgxpool.Pool, store *quota.Store, scopes []quota.Scope, now time.Time) (int, error) {
	if len(scopes) == 0 {
		return 0, nil
	}
	used, err := TokensToday(ctx, pool, now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sc := range scopes {
		var total int64
		for _, u := range used {
			if sc.Matches(u.Team, u.Application) {
				total += u.Tokens
			}
		}
		if store.SeedTokensPerDay(sc, total) {
			n++
		}
	}
	return n, nil
}

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
	energy, co2                      float64
	hasEnergy, hasCO2                bool
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
	EnergyWh        *float64  `json:"energy_wh"`
	CO2eGrams       *float64  `json:"co2e_g"`
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
		if e.EnergyWh != nil {
			s.energy += *e.EnergyWh
			s.hasEnergy = true
		}
		if e.CO2eGrams != nil {
			s.co2 += *e.CO2eGrams
			s.hasCO2 = true
		}
	}
	b := &pgx.Batch{}
	for k, s := range acc {
		var cost *int64
		if s.hasCost {
			cost = &s.cost
		}
		var energy, co2 *float64
		if s.hasEnergy {
			energy = &s.energy
		}
		if s.hasCO2 {
			co2 = &s.co2
		}
		b.Queue(`
INSERT INTO usage_hourly (hour, team, application, principal, model, backend, outcome,
                          requests, usage_unknown, input_tokens, output_tokens, cached_tokens, reasoning_tokens, cost_micro_eur,
                          energy_wh, co2e_g)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (hour, team, application, principal, model, backend, outcome) DO UPDATE SET
    requests         = usage_hourly.requests + EXCLUDED.requests,
    usage_unknown    = usage_hourly.usage_unknown + EXCLUDED.usage_unknown,
    input_tokens     = usage_hourly.input_tokens + EXCLUDED.input_tokens,
    output_tokens    = usage_hourly.output_tokens + EXCLUDED.output_tokens,
    cached_tokens    = usage_hourly.cached_tokens + EXCLUDED.cached_tokens,
    reasoning_tokens = usage_hourly.reasoning_tokens + EXCLUDED.reasoning_tokens,
    cost_micro_eur   = CASE WHEN usage_hourly.cost_micro_eur IS NULL AND EXCLUDED.cost_micro_eur IS NULL THEN NULL
                            ELSE COALESCE(usage_hourly.cost_micro_eur, 0) + COALESCE(EXCLUDED.cost_micro_eur, 0) END,
    energy_wh        = CASE WHEN usage_hourly.energy_wh IS NULL AND EXCLUDED.energy_wh IS NULL THEN NULL
                            ELSE COALESCE(usage_hourly.energy_wh, 0) + COALESCE(EXCLUDED.energy_wh, 0) END,
    co2e_g           = CASE WHEN usage_hourly.co2e_g IS NULL AND EXCLUDED.co2e_g IS NULL THEN NULL
                            ELSE COALESCE(usage_hourly.co2e_g, 0) + COALESCE(EXCLUDED.co2e_g, 0) END`,
			k.hour, k.team, k.application, k.principal, k.model, k.backend, k.outcome,
			s.requests, s.unknown, s.input, s.output, s.cached, s.reasoning, cost, energy, co2)
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

// TeamApp is what one team and application used: tokens, or micro-euros,
// depending on the query.
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
	return usedSince(ctx, pool, time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC),
		`input_tokens + output_tokens`,
		`COALESCE((o.payload->>'input_tokens')::bigint, 0) + COALESCE((o.payload->>'output_tokens')::bigint, 0)`)
}

// SpentThisMonth returns the money (micro-euros, in TeamApp.Tokens) spent since
// the 1st of the month of now, UTC, the same way.
func SpentThisMonth(ctx context.Context, pool *pgxpool.Pool, now time.Time) ([]TeamApp, error) {
	n := now.UTC()
	return usedSince(ctx, pool, time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC),
		`COALESCE(cost_micro_eur, 0)`,
		`COALESCE((o.payload->>'cost_micro_eur')::bigint, 0)`)
}

// usedSince sums an amount over the hourly sums from since on, plus the usage
// events after the rollup's cursor that happened since then. rolled and tail
// are SQL expressions for the same quantity in the two places.
func usedSince(ctx context.Context, pool *pgxpool.Pool, since time.Time, rolled, tail string) ([]TeamApp, error) {
	rs, err := pool.Query(ctx, `
WITH cur AS (
    SELECT COALESCE((SELECT last_xid FROM outbox_consumers WHERE name = $2), 0) AS xid,
           COALESCE((SELECT last_seq FROM outbox_consumers WHERE name = $2), 0) AS seq
), rolled AS (
    SELECT team, application, sum(`+rolled+`) AS amount
    FROM usage_hourly WHERE hour >= $1 GROUP BY team, application
), tail AS (
    SELECT o.payload->>'team' AS team, o.payload->>'application' AS application, sum(`+tail+`) AS amount
    FROM outbox o, cur
    WHERE o.kind = $3 AND (o.xid, o.seq) > (cur.xid::text::xid8, cur.seq)
      AND (o.payload->>'time')::timestamptz >= $1
    GROUP BY 1, 2
)
SELECT team, application, sum(amount)::bigint
FROM (SELECT * FROM rolled UNION ALL SELECT * FROM tail) u
GROUP BY team, application`, since, ConsumerName, KindUsage)
	if err != nil {
		return nil, fmt.Errorf("usage since %s: %w", since.Format(time.DateOnly), err)
	}
	defer rs.Close()
	var out []TeamApp
	for rs.Next() {
		var t TeamApp
		var team, app *string
		if err := rs.Scan(&team, &app, &t.Tokens); err != nil {
			return nil, fmt.Errorf("usage since %s: %w", since.Format(time.DateOnly), err)
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

// Scopes are the scopes that have a daily token limit and a monthly budget.
type Scopes struct{ Daily, Monthly []quota.Scope }

// Seed gives the daily token counters and the monthly budget counters of store
// the usage already recorded, for the scopes that have a limit. A counter that
// exists is left alone: it knows better. It returns how many counters it set.
func Seed(ctx context.Context, pool *pgxpool.Pool, store *quota.Store, scopes Scopes, now time.Time) (int, error) {
	n := 0
	if len(scopes.Daily) > 0 {
		used, err := TokensToday(ctx, pool, now)
		if err != nil {
			return 0, err
		}
		for _, sc := range scopes.Daily {
			if store.SeedTokensPerDay(sc, sumFor(sc, used)) {
				n++
			}
		}
	}
	if len(scopes.Monthly) > 0 {
		spent, err := SpentThisMonth(ctx, pool, now)
		if err != nil {
			return n, err
		}
		for _, sc := range scopes.Monthly {
			if store.SeedBudget(sc, sumFor(sc, spent)) {
				n++
			}
		}
	}
	return n, nil
}

func sumFor(sc quota.Scope, used []TeamApp) int64 {
	var total int64
	for _, u := range used {
		if sc.Matches(u.Team, u.Application) {
			total += u.Tokens
		}
	}
	return total
}

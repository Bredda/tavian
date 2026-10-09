package outbox

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pruner removes old events from the outbox so that it does not grow for ever.
//
// It removes a row only when all of these hold: the row is older than the
// retention of its kind; every registered consumer has handled it (a consumer
// that is new or stopped holds pruning back, which is safe); and, for decision
// records, the row is in the audit chain under a signed seal, which is what
// keeps the record provable once its content is gone. Chain entries, seals,
// rollups and configuration revisions are never removed. What each batch
// removed is written to outbox_prunes in the same transaction, so that
// `tavian verify-audit` can account for the missing records.
type Pruner struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger
	// Keep is how long events of each kind are kept; a kind that is absent or
	// has no positive duration is never pruned.
	Keep map[string]time.Duration
	// Every is how often a pass runs (default 1h). Batch is how many rows one
	// transaction removes (default 1000).
	Every time.Duration
	Batch int
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// OnPruned, when set, hears about every batch.
	OnPruned func(kind string, rows int64)
	// OnError, when set, hears about failed passes.
	OnError func(error)
}

const (
	// KindDecision and KindUsage are the kinds of event that are pruned.
	KindDecision = "decision"
	KindUsage    = "usage"

	defaultPruneEvery = time.Hour
	defaultPruneBatch = 1000
	// a pass never runs longer than this, so a huge backlog is worked off over
	// several passes without hogging the database
	maxPassTime = 5 * time.Minute
)

func (p *Pruner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run prunes every p.Every until ctx is done.
func (p *Pruner) Run(ctx context.Context) {
	every := p.Every
	if every <= 0 {
		every = defaultPruneEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := p.Once(ctx); err != nil && ctx.Err() == nil {
			p.Log.Error("outbox pruning failed", "error", err)
			if p.OnError != nil {
				p.OnError(err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once runs one pass and returns how many rows it removed, by kind.
func (p *Pruner) Once(ctx context.Context) (map[string]int64, error) {
	removed := map[string]int64{}
	ctx, cancel := context.WithTimeout(ctx, maxPassTime)
	defer cancel()
	for _, kind := range []string{KindUsage, KindDecision} {
		keep := p.Keep[kind]
		if keep <= 0 {
			continue
		}
		before := p.now().Add(-keep)
		for ctx.Err() == nil {
			n, skipped, err := p.batch(ctx, kind, before)
			if err != nil {
				return removed, fmt.Errorf("prune %s: %w", kind, err)
			}
			if skipped {
				return removed, nil // another instance is pruning
			}
			removed[kind] += n
			if n > 0 && p.OnPruned != nil {
				p.OnPruned(kind, n)
			}
			if n < int64(p.batchSize()) {
				break
			}
		}
	}
	return removed, nil
}

func (p *Pruner) batchSize() int {
	if p.Batch > 0 {
		return p.Batch
	}
	return defaultPruneBatch
}

// batch removes up to one batch of eligible rows of kind recorded before
// cutoff, and logs it, in one transaction.
func (p *Pruner) batch(ctx context.Context, kind string, cutoff time.Time) (n int64, skipped bool, err error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema() || ':outbox-prune', 0))`).Scan(&locked); err != nil {
		return 0, false, err
	}
	if !locked {
		return 0, true, nil
	}

	// decision records also need a signed seal over their chain entry
	sealed := ""
	if kind == KindDecision {
		sealed = ` AND EXISTS (SELECT 1 FROM audit_chain c WHERE c.event_id = o.event_id
		            AND c.position <= (SELECT COALESCE(max(last_position), 0) FROM audit_seals))`
	}
	rs, err := tx.Query(ctx, `
WITH slowest AS (SELECT last_xid, last_seq FROM outbox_consumers ORDER BY last_xid, last_seq LIMIT 1),
doomed AS (
    SELECT o.seq FROM outbox o, slowest
    WHERE o.kind = $1 AND o.recorded_at < $2
      AND (o.xid, o.seq) <= (slowest.last_xid::text::xid8, slowest.last_seq)`+sealed+`
    ORDER BY o.seq LIMIT $3 FOR UPDATE OF o SKIP LOCKED)
DELETE FROM outbox WHERE seq IN (SELECT seq FROM doomed) RETURNING event_id`, kind, cutoff, p.batchSize())
	if err != nil {
		return 0, false, err
	}
	var ids []string
	for rs.Next() {
		var id string
		if err := rs.Scan(&id); err != nil {
			rs.Close()
			return 0, false, err
		}
		ids = append(ids, id)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return 0, false, err
	}
	if len(ids) == 0 {
		return 0, false, nil
	}
	var through *int64
	if kind == KindDecision {
		if err := tx.QueryRow(ctx, `SELECT max(position) FROM audit_chain WHERE event_id = ANY($1)`, ids).Scan(&through); err != nil {
			return 0, false, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox_prunes (kind, rows, through_position) VALUES ($1, $2, $3)`, kind, len(ids), through); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return int64(len(ids)), false, nil
}

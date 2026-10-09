// Package outbox runs the consumers of the transactional outbox (ADR-0010).
//
// Events are appended to the outbox table by the data plane; consumers read
// them in order, in batches, and keep a cursor in PostgreSQL. A consumer's
// effects and its cursor move in one transaction, so what it writes to the
// database happens exactly once even if the process dies half way. A
// consumer runs on one instance at a time, whatever the number of replicas.
//
// Reading in order is not as simple as "everything after the last seq":
// outbox.seq is assigned when a row is inserted, not when its transaction
// commits, so a row with a lower seq can become visible after a row with a
// higher one, and a cursor that has moved past it would never return. Rows are
// therefore read by the transaction that inserted them (xid) and only once
// every older transaction has finished (see migration 0003).
package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Row is an event read from the outbox.
type Row struct {
	Seq        int64
	XID        int64
	EventID    string
	Kind       string
	OccurredAt time.Time
	// Payload is the JSON document as PostgreSQL holds it (jsonb), which does
	// not keep the bytes that were inserted: key order and spacing differ.
	Payload []byte
}

// Consumer handles events.
type Consumer interface {
	// Name identifies the consumer and its cursor; it must never change.
	Name() string
	// Kinds are the kinds of event the consumer wants.
	Kinds() []string
	// Handle processes a batch in tx, the transaction that also moves the
	// cursor: when it returns an error nothing it wrote is kept and the batch
	// comes back. Batches are in order and may be empty; the consumer then
	// has a chance to act on time alone.
	Handle(ctx context.Context, tx pgx.Tx, batch []Row) error
}

// Cycle describes one turn of a consumer, for metrics and logs.
type Cycle struct {
	Consumer string
	// Handled is the number of events in the batch.
	Handled int
	// Pending is how many events are waiting after the turn (capped).
	Pending int64
	// Skipped is true when another instance holds the consumer.
	Skipped bool
	Err     error
}

// Defaults for the zero values of Runner's fields.
const (
	DefaultPollEvery = time.Second
	DefaultBatchSize = 500
	maxBackoff       = 30 * time.Second
	pendingCap       = 10000
)

// Runner runs consumers until its context is done.
type Runner struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger
	// PollEvery is how long a consumer waits when it has caught up.
	PollEvery time.Duration
	BatchSize int
	// OnCycle, when set, hears about every turn of every consumer.
	OnCycle func(Cycle)

	consumers []Consumer
}

// Add registers a consumer. Call it before Run.
func (r *Runner) Add(c Consumer) { r.consumers = append(r.consumers, c) }

func (r *Runner) poll() time.Duration {
	if r.PollEvery > 0 {
		return r.PollEvery
	}
	return DefaultPollEvery
}

func (r *Runner) batch() int {
	if r.BatchSize > 0 {
		return r.BatchSize
	}
	return DefaultBatchSize
}

// Run starts every consumer and returns when ctx is done and they have all
// stopped.
func (r *Runner) Run(ctx context.Context) {
	done := make(chan struct{}, len(r.consumers))
	for _, c := range r.consumers {
		go func() {
			defer func() { done <- struct{}{} }()
			r.loop(ctx, c)
		}()
	}
	for range r.consumers {
		<-done
	}
}

func (r *Runner) loop(ctx context.Context, c Consumer) {
	backoff := r.poll()
	for ctx.Err() == nil {
		cy, more := r.Step(ctx, c)
		if r.OnCycle != nil {
			r.OnCycle(cy)
		}
		wait := r.poll()
		switch {
		case cy.Err != nil:
			if ctx.Err() != nil {
				return
			}
			r.Log.Error("outbox consumer failed, will retry", "consumer", c.Name(), "error", cy.Err, "retry_in", backoff)
			wait = backoff
			backoff = min(backoff*2, maxBackoff)
		case more:
			backoff = r.poll()
			continue
		default:
			backoff = r.poll()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Step runs one turn of c: it reads a batch, hands it over and moves the
// cursor. more is true when the batch was full, i.e. there may be more.
func (r *Runner) Step(ctx context.Context, c Consumer) (cy Cycle, more bool) {
	cy = Cycle{Consumer: c.Name()}
	more, cy.Handled, cy.Skipped, cy.Err = r.step(ctx, c)
	if cy.Err == nil && !cy.Skipped {
		cy.Pending = r.pending(ctx, c)
	}
	return cy, more
}

func (r *Runner) step(ctx context.Context, c Consumer) (more bool, handled int, skipped bool, err error) {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return false, 0, false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// One instance at a time. The lock is held until the transaction ends and
	// is per schema, so independent databases (and tests) do not share it.
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema() || ':outbox:' || $1::text, 0))`, c.Name()).Scan(&locked); err != nil {
		return false, 0, false, fmt.Errorf("lock: %w", err)
	}
	if !locked {
		return false, 0, true, nil
	}

	cur, err := readCursor(ctx, tx, c.Name())
	if err != nil {
		return false, 0, false, err
	}
	limit := r.batch()
	rows, horizon, err := fetch(ctx, tx, cur, c.Kinds(), limit)
	if err != nil {
		return false, 0, false, err
	}
	if err := c.Handle(ctx, tx, rows); err != nil {
		return false, 0, false, fmt.Errorf("%s: %w", c.Name(), err)
	}

	next := cur
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next = cursor{xid: last.XID, seq: last.Seq}
		more = true
	} else if h := (cursor{xid: horizon - 1, seq: math.MaxInt64}); h.after(cur) {
		// Everything wanted below the horizon has been seen: skip the rows of
		// other kinds without reading them again.
		next = h
	}
	if next != cur {
		if _, err := tx.Exec(ctx, `UPDATE outbox_consumers SET last_xid = $2, last_seq = $3, updated_at = now() WHERE name = $1`, c.Name(), next.xid, next.seq); err != nil {
			return false, 0, false, fmt.Errorf("move cursor: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, 0, false, fmt.Errorf("commit: %w", err)
	}
	return more, len(rows), false, nil
}

type cursor struct{ xid, seq int64 }

func (a cursor) after(b cursor) bool {
	return a.xid > b.xid || (a.xid == b.xid && a.seq > b.seq)
}

// Register creates the cursors of the consumers. Run it once before Run, so
// that the turns themselves never write a row of their own (and never hold
// back the horizon of the other consumers).
func (r *Runner) Register(ctx context.Context) error {
	for _, c := range r.consumers {
		if _, err := r.Pool.Exec(ctx, `INSERT INTO outbox_consumers (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, c.Name()); err != nil {
			return fmt.Errorf("register consumer %s: %w", c.Name(), err)
		}
	}
	return nil
}

func readCursor(ctx context.Context, tx pgx.Tx, name string) (cursor, error) {
	var cur cursor
	err := tx.QueryRow(ctx, `SELECT last_xid, last_seq FROM outbox_consumers WHERE name = $1`, name).Scan(&cur.xid, &cur.seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return cur, fmt.Errorf("consumer %s is not registered", name)
	}
	if err != nil {
		return cur, fmt.Errorf("read cursor: %w", err)
	}
	return cur, nil
}

// fetch reads up to limit rows after cur, in order, that are final, and the
// horizon it used: the oldest transaction still running. One statement, so
// the rows and the horizon come from the same snapshot.
func fetch(ctx context.Context, tx pgx.Tx, cur cursor, kinds []string, limit int) ([]Row, int64, error) {
	rs, err := tx.Query(ctx, `
WITH h AS (SELECT pg_snapshot_xmin(pg_current_snapshot()) AS x)
SELECT h.x::text, o.seq, o.xid::text, o.event_id, o.kind, o.occurred_at, o.payload::text
FROM h LEFT JOIN LATERAL (
    SELECT seq, xid, event_id, kind, occurred_at, payload
    FROM outbox
    WHERE xid < h.x AND (xid, seq) > ($1::bigint::text::xid8, $2::bigint) AND kind = ANY($3::text[])
    ORDER BY xid, seq
    LIMIT $4) o ON true`, cur.xid, cur.seq, kinds, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("read outbox: %w", err)
	}
	defer rs.Close()
	var (
		rows    []Row
		horizon int64
	)
	for rs.Next() {
		var (
			hstr          string
			seq           *int64
			xid, id, kind *string
			payload       *string
			at            *time.Time
		)
		if err := rs.Scan(&hstr, &seq, &xid, &id, &kind, &at, &payload); err != nil {
			return nil, 0, fmt.Errorf("read outbox: %w", err)
		}
		if horizon, err = strconv.ParseInt(hstr, 10, 64); err != nil {
			return nil, 0, fmt.Errorf("read outbox: horizon %q: %w", hstr, err)
		}
		if seq == nil {
			continue // the horizon alone: nothing to read
		}
		x, err := strconv.ParseInt(*xid, 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("read outbox: xid %q: %w", *xid, err)
		}
		rows = append(rows, Row{Seq: *seq, XID: x, EventID: *id, Kind: *kind, OccurredAt: *at, Payload: []byte(*payload)})
	}
	if err := rs.Err(); err != nil {
		return nil, 0, fmt.Errorf("read outbox: %w", err)
	}
	return rows, horizon, nil
}

// pending counts the events a consumer has yet to see, up to a cap, for
// metrics. It looks at the committed state and never fails a turn.
func (r *Runner) pending(ctx context.Context, c Consumer) int64 {
	var n int64
	err := r.Pool.QueryRow(ctx, `
SELECT count(*) FROM (
    SELECT 1 FROM outbox o, outbox_consumers k
    WHERE k.name = $1 AND o.xid < pg_snapshot_xmin(pg_current_snapshot())
      AND (o.xid, o.seq) > (k.last_xid::text::xid8, k.last_seq) AND o.kind = ANY($2::text[])
    LIMIT $3) t`, c.Name(), c.Kinds(), pendingCap+1).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

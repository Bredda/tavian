package meter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/bredda/tavian/internal/spool"
	"github.com/bredda/tavian/internal/store"
)

// KindUsage is the outbox kind of a UsageEvent.
const KindUsage = "usage"

// envelope is one line of the spool: the event and what is needed to store it
// again without knowing its type. Lines written before envelopes existed hold a
// bare usage event; they have no "kind" and are read as such.
type envelope struct {
	Kind    string          `json:"kind"`
	ID      string          `json:"id"`
	At      time.Time       `json:"at"`
	Payload json.RawMessage `json:"payload"`
}

// ErrAuditUnavailable means an event could be neither stored nor spooled. The
// gateway fails closed on it (ADR-0005).
var ErrAuditUnavailable = errors.New("audit trail unavailable")

// Admitter is implemented by sinks that can tell, before a request is served,
// whether its event could still be recorded.
type Admitter interface {
	Admit() error
}

// OutboxStore is the part of the database the sink needs.
type OutboxStore interface {
	InsertOutbox(ctx context.Context, rows []store.OutboxRow) error
}

// OutboxSink writes usage events to the PostgreSQL outbox (ADR-0010). While
// the database is unavailable it appends them to a bounded disk spool and
// replays them once the database is back. It never drops an event silently:
// when neither works, Emit fails and Admit starts refusing new requests.
type OutboxSink struct {
	Store OutboxStore
	Spool *spool.Spool
	Log   *slog.Logger
	// Timeout bounds one database write on the request path.
	Timeout time.Duration
	// FlushEvery is how often the replay loop looks at the spool.
	FlushEvery time.Duration

	down     atomic.Bool
	rejected atomic.Int64
}

// Rejected counts spooled records that could not be read and were set aside.
func (s *OutboxSink) Rejected() int64 { return s.rejected.Load() }

// DefaultFlushEvery and DefaultEmitTimeout apply when the fields are zero.
const (
	DefaultFlushEvery  = 2 * time.Second
	DefaultEmitTimeout = 2 * time.Second
	replayBatch        = 200
)

// Emit stores the event, falling back to the spool.
func (s *OutboxSink) Emit(ctx context.Context, e Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode %s event: %w", e.Kind(), err)
	}
	// While the database is down, or events are waiting to be replayed, go
	// straight to the spool: no timeout per request, and replay order is kept.
	if !s.down.Load() && s.Spool.Size() == 0 {
		tctx, cancel := context.WithTimeout(ctx, s.timeout())
		err := s.Store.InsertOutbox(tctx, []store.OutboxRow{rowOf(e, payload)})
		cancel()
		if err == nil {
			return nil
		}
		if !s.down.Swap(true) {
			s.Log.Error("database unavailable, spooling events to disk", "error", err)
		}
	}
	line, err := json.Marshal(envelope{Kind: e.Kind(), ID: e.ID(), At: e.At(), Payload: payload})
	if err != nil {
		return fmt.Errorf("encode %s event: %w", e.Kind(), err)
	}
	if err := s.Spool.Append(line); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// Admit refuses new requests once the spool has no headroom left while the
// database is down. The headroom (a tenth of the spool) is kept for requests
// already in flight, whose events are owed.
func (s *OutboxSink) Admit() error {
	if s.down.Load() && s.Spool.Remaining() < s.Spool.Capacity()/10 {
		return ErrAuditUnavailable
	}
	return nil
}

// Up reports whether the database is believed reachable.
func (s *OutboxSink) Up() bool { return !s.down.Load() }

// Run replays spooled events until ctx is done, then tries once more so a
// clean shutdown leaves as little as possible on disk.
func (s *OutboxSink) Run(ctx context.Context) {
	every := s.FlushEvery
	if every <= 0 {
		every = DefaultFlushEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.flush(fctx)
			cancel()
			return
		case <-t.C:
			if s.down.Load() || s.Spool.Size() > 0 {
				s.flush(ctx)
			}
		}
	}
}

func (s *OutboxSink) flush(ctx context.Context) {
	err := s.Spool.Drain(ctx, replayBatch, func(batch [][]byte) error {
		rows := make([]store.OutboxRow, 0, len(batch))
		for _, rec := range batch {
			row, ok := rowOfSpooled(rec)
			if !ok {
				// A torn write after a crash, or a record from a future
				// version. It is set aside rather than dropped, and one bad
				// line must not block the rest of the queue.
				s.rejected.Add(1)
				s.Log.Error("setting aside unreadable spooled record", "bytes", len(rec))
				if err := s.Spool.Reject(rec); err != nil {
					return fmt.Errorf("keep rejected record: %w", err)
				}
				continue
			}
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			return nil
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return s.Store.InsertOutbox(wctx, rows)
	})
	switch {
	case err != nil:
		if ctx.Err() == nil && s.down.CompareAndSwap(false, true) {
			s.Log.Error("replaying spooled events failed", "error", err)
		}
	case s.Spool.Size() == 0 && s.down.CompareAndSwap(true, false):
		s.Log.Info("database available again, spool drained")
	}
}

func rowOf(e Event, payload []byte) store.OutboxRow {
	return store.OutboxRow{EventID: e.ID(), Kind: e.Kind(), OccurredAt: e.At(), Payload: payload}
}

// rowOfSpooled reads one spool line, in either format.
func rowOfSpooled(rec []byte) (store.OutboxRow, bool) {
	var env envelope
	if err := json.Unmarshal(rec, &env); err != nil {
		return store.OutboxRow{}, false
	}
	if env.Kind == "" { // legacy: a bare usage event
		var e UsageEvent
		if err := json.Unmarshal(rec, &e); err != nil || e.EventID == "" {
			return store.OutboxRow{}, false
		}
		return rowOf(e, rec), true
	}
	if env.ID == "" || len(env.Payload) == 0 {
		return store.OutboxRow{}, false
	}
	return store.OutboxRow{EventID: env.ID, Kind: env.Kind, OccurredAt: env.At, Payload: env.Payload}, true
}

func (s *OutboxSink) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultEmitTimeout
}

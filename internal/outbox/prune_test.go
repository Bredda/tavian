package outbox

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/store"
)

// A pruning test has two consumers of usage events; "slow" is the one that
// can be left behind.
type pruneEnv struct {
	t      *testing.T
	st     *store.Store
	runner *Runner
	fast   *collector
	slow   *collector
}

func newPruneEnv(t *testing.T) *pruneEnv {
	t.Helper()
	st, r, fast := setup(t, "usage", "decision")
	fast.name = "fast"
	slow := &collector{name: "slow", kinds: []string{"usage", "decision"}}
	r.Add(slow)
	if err := r.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	// setup registered the cursor of "test", which nothing here runs
	if _, err := st.Pool().Exec(context.Background(), `DELETE FROM outbox_consumers WHERE name = 'test'`); err != nil {
		t.Fatal(err)
	}
	return &pruneEnv{t: t, st: st, runner: r, fast: fast, slow: slow}
}

func (e *pruneEnv) old(kind string, n int, age time.Duration, prefix string) []string {
	e.t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("%s-%d", prefix, i))
	}
	insert(e.t, e.st, kind, ids...)
	if _, err := e.st.Pool().Exec(context.Background(), `UPDATE outbox SET recorded_at = now() - $1::bigint * interval '1 second' WHERE event_id = ANY($2)`, int64(age.Seconds()), ids); err != nil {
		e.t.Fatal(err)
	}
	return ids
}

func (e *pruneEnv) consume(c *collector) {
	e.t.Helper()
	waitFinal(e.t, e.st)
	for i := 0; i < 50; i++ {
		cy, more := e.runner.Step(context.Background(), c)
		if cy.Err != nil {
			e.t.Fatal(cy.Err)
		}
		if !more {
			return
		}
	}
}

func (e *pruneEnv) remaining() map[string]bool {
	e.t.Helper()
	rs, err := e.st.Pool().Query(context.Background(), `SELECT event_id FROM outbox`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rs.Close()
	out := map[string]bool{}
	for rs.Next() {
		var id string
		_ = rs.Scan(&id)
		out[id] = true
	}
	return out
}

func (e *pruneEnv) pruner(keep map[string]time.Duration) *Pruner {
	return &Pruner{Pool: e.st.Pool(), Log: slog.New(slog.DiscardHandler), Keep: keep, Batch: 100}
}

const day = 24 * time.Hour

func TestPruneKeepsWhatAConsumerHasNotRead(t *testing.T) {
	e := newPruneEnv(t)
	e.old("usage", 3, 100*day, "old")
	e.consume(e.fast)
	p := e.pruner(map[string]time.Duration{"usage": 90 * day})
	if n, err := p.Once(context.Background()); err != nil || n["usage"] != 0 {
		t.Fatalf("removed %v (%v) while a consumer had read nothing", n, err)
	}
	e.consume(e.slow)
	n, err := p.Once(context.Background())
	if err != nil || n["usage"] != 3 {
		t.Fatalf("removed %v (%v), want the 3 old rows once both consumers read them", n, err)
	}
}

func TestPruneKeepsYoungRowsAndOtherKinds(t *testing.T) {
	e := newPruneEnv(t)
	e.old("usage", 2, 100*day, "old")
	e.old("usage", 2, 10*day, "young")
	e.old("decision", 2, 400*day, "dec")
	e.consume(e.fast)
	e.consume(e.slow)
	p := e.pruner(map[string]time.Duration{"usage": 90 * day}) // decisions: no retention
	n, err := p.Once(context.Background())
	if err != nil || n["usage"] != 2 || n["decision"] != 0 {
		t.Fatalf("removed %v (%v)", n, err)
	}
	left := e.remaining()
	for _, id := range []string{"young-0", "young-1", "dec-0", "dec-1"} {
		if !left[id] {
			t.Errorf("%s was removed", id)
		}
	}
	if left["old-0"] || left["old-1"] {
		t.Error("old usage rows were kept")
	}
}

func TestPruneNeverRemovesWithoutRetentionOrConsumers(t *testing.T) {
	e := newPruneEnv(t)
	e.old("usage", 2, 1000*day, "old")
	e.consume(e.fast)
	e.consume(e.slow)
	for name, keep := range map[string]map[string]time.Duration{
		"no retention": nil, "zero": {"usage": 0}, "negative": {"usage": -day},
	} {
		if n, err := e.pruner(keep).Once(context.Background()); err != nil || n["usage"] != 0 {
			t.Errorf("%s: removed %v (%v)", name, n, err)
		}
	}
	// no consumer registered: nothing has been read by anybody
	if _, err := e.st.Pool().Exec(context.Background(), `DELETE FROM outbox_consumers`); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.pruner(map[string]time.Duration{"usage": day}).Once(context.Background()); n["usage"] != 0 {
		t.Errorf("removed %v with no consumer registered", n)
	}
	if len(e.remaining()) != 2 {
		t.Error("rows were lost")
	}
}

func TestDecisionRecordsAreRemovedOnlyUnderASignedSeal(t *testing.T) {
	e := newPruneEnv(t)
	ids := e.old("decision", 5, 400*day, "d")
	e.consume(e.fast)
	e.consume(e.slow)
	p := e.pruner(map[string]time.Duration{"decision": 365 * day})
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.st.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	if n, _ := p.Once(ctx); n["decision"] != 0 {
		t.Fatalf("removed %v records that are not in the chain", n)
	}
	// chain all five, seal the first three
	for i, id := range ids {
		exec(`INSERT INTO audit_chain (position, event_id, occurred_at, content_hash, prev_hash, entry_hash) VALUES ($1, $2, now(), '\x00', '\x00', '\x00')`, i+1, id)
	}
	if n, _ := p.Once(ctx); n["decision"] != 0 {
		t.Fatalf("removed %v records that no seal covers", n)
	}
	exec(`INSERT INTO audit_seals (id, first_position, last_position, last_entry_hash, sealed_at, key_id, signature) VALUES (1, 1, 3, '\x00', now(), 'k', '\x00')`)
	n, err := p.Once(ctx)
	if err != nil || n["decision"] != 3 {
		t.Fatalf("removed %v (%v), want the 3 sealed records", n, err)
	}
	left := e.remaining()
	if left["d-0"] || left["d-1"] || left["d-2"] || !left["d-3"] || !left["d-4"] {
		t.Fatalf("left %v", left)
	}
	var rows int64
	var through *int64
	var kind string
	if err := e.st.Pool().QueryRow(ctx, `SELECT kind, rows, through_position FROM outbox_prunes`).Scan(&kind, &rows, &through); err != nil {
		t.Fatal(err)
	}
	if kind != "decision" || rows != 3 || through == nil || *through != 3 {
		t.Fatalf("prune log = %s %d %v", kind, rows, through)
	}
}

func TestPruneWorksInBatchesAndLogsEachOne(t *testing.T) {
	e := newPruneEnv(t)
	e.old("usage", 5, 100*day, "old")
	e.consume(e.fast)
	e.consume(e.slow)
	p := e.pruner(map[string]time.Duration{"usage": 90 * day})
	p.Batch = 2
	var batches []int64
	p.OnPruned = func(_ string, n int64) { batches = append(batches, n) }
	n, err := p.Once(context.Background())
	if err != nil || n["usage"] != 5 {
		t.Fatalf("removed %v (%v)", n, err)
	}
	if fmt.Sprint(batches) != "[2 2 1]" {
		t.Errorf("batches = %v", batches)
	}
	var logged, rows int64
	if err := e.st.Pool().QueryRow(context.Background(), `SELECT count(*), sum(rows) FROM outbox_prunes`).Scan(&logged, &rows); err != nil || logged != 3 || rows != 5 {
		t.Fatalf("log = %d batches, %d rows (%v)", logged, rows, err)
	}
}

func TestOnlyOnePrunerRunsAtATime(t *testing.T) {
	e := newPruneEnv(t)
	e.old("usage", 2, 100*day, "old")
	e.consume(e.fast)
	e.consume(e.slow)
	ctx := context.Background()
	tx, err := e.st.Pool().Begin(ctx) // another instance, in the middle of a batch
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema() || ':outbox-prune', 0))`).Scan(&locked); err != nil || !locked {
		t.Fatal("setup")
	}
	if n, err := e.pruner(map[string]time.Duration{"usage": 90 * day}).Once(ctx); err != nil || n["usage"] != 0 {
		t.Fatalf("removed %v (%v) while another instance holds the lock", n, err)
	}
	_ = tx.Rollback(ctx)
	if n, _ := e.pruner(map[string]time.Duration{"usage": 90 * day}).Once(ctx); n["usage"] != 2 {
		t.Fatalf("removed %v after the lock was released", n)
	}
}

// What the administrators changed is evidence: no retention removes it, even
// when someone asks for one.
func TestAdminChangesAreNeverPruned(t *testing.T) {
	e := newPruneEnv(t)
	e.old("admin_change", 2, 1000*day, "adm")
	e.old("usage", 1, 100*day, "old")
	e.consume(e.fast)
	e.consume(e.slow)
	p := e.pruner(map[string]time.Duration{"usage": 90 * day, "decision": day, "admin_change": day})
	n, err := p.Once(context.Background())
	if err != nil || n["admin_change"] != 0 {
		t.Fatalf("removed %v (%v)", n, err)
	}
	if left := e.remaining(); !left["adm-0"] || !left["adm-1"] {
		t.Error("an admin change was removed")
	}
}

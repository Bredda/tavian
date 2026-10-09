package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

// These tests need a PostgreSQL: see internal/store/storetest.

type collector struct {
	name  string
	kinds []string

	mu      sync.Mutex
	ids     []string
	batches int
	fail    error
	enter   chan struct{} // closed-over signals for the exclusivity test
	release chan struct{}
}

func (c *collector) Name() string    { return c.name }
func (c *collector) Kinds() []string { return c.kinds }

func (c *collector) Handle(_ context.Context, tx pgx.Tx, batch []Row) error {
	if c.enter != nil {
		close(c.enter)
		<-c.release
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches++
	if c.fail != nil {
		return c.fail
	}
	// a side effect in the consumer's transaction
	for _, r := range batch {
		if _, err := tx.Exec(context.Background(), `INSERT INTO seen (event_id) VALUES ($1)`, r.EventID); err != nil {
			return err
		}
		c.ids = append(c.ids, r.EventID)
	}
	return nil
}

func (c *collector) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.ids)
}

func setup(t *testing.T, kinds ...string) (*store.Store, *Runner, *collector) {
	t.Helper()
	st, _ := storetest.New(t)
	ctx := context.Background()
	if _, err := st.Pool().Exec(ctx, `CREATE TABLE seen (event_id text)`); err != nil {
		t.Fatal(err)
	}
	if len(kinds) == 0 {
		kinds = []string{"decision"}
	}
	c := &collector{name: "test", kinds: kinds}
	r := &Runner{Pool: st.Pool(), Log: slog.New(slog.DiscardHandler), BatchSize: 3}
	r.Add(c)
	if err := r.Register(ctx); err != nil {
		t.Fatal(err)
	}
	return st, r, c
}

func insert(t *testing.T, st *store.Store, kind string, ids ...string) {
	t.Helper()
	var rows []store.OutboxRow
	for _, id := range ids {
		rows = append(rows, store.OutboxRow{EventID: id, Kind: kind, OccurredAt: time.Now(), Payload: []byte(`{"id":"` + id + `"}`)})
	}
	if err := st.InsertOutbox(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
}

// drain runs turns until the consumer has caught up.
func drain(t *testing.T, r *Runner, c Consumer) {
	t.Helper()
	for i := 0; i < 50; i++ {
		cy, more := r.Step(context.Background(), c)
		if cy.Err != nil {
			t.Fatal(cy.Err)
		}
		if !more {
			return
		}
	}
	t.Fatal("never caught up")
}

// catchUpTo runs turns until the consumer has seen n events. A transaction
// running anywhere in the cluster (other tests, here) holds the horizon back
// for a moment, so a single turn right after an insert may see nothing yet:
// that is latency, never loss.
func catchUpTo(t *testing.T, r *Runner, c *collector, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(c.seen()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("seen %v, want %d events", c.seen(), n)
		}
		if cy, _ := r.Step(context.Background(), c); cy.Err != nil {
			t.Fatal(cy.Err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitFinal waits until every row of the outbox is below the horizon.
func waitFinal(t *testing.T, st *store.Store) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var total, final int
		err := st.Pool().QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE xid < pg_snapshot_xmin(pg_current_snapshot())) FROM outbox`).Scan(&total, &final)
		if err != nil {
			t.Fatal(err)
		}
		if total == final {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the horizon never passed the rows")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestConsumerSeesEveryRowOnceInOrder(t *testing.T) {
	st, r, c := setup(t)
	var want []string
	for i := 0; i < 4; i++ {
		ids := []string{fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)}
		want = append(want, ids...)
		insert(t, st, "decision", ids...)
	}
	catchUpTo(t, r, c, len(want))
	drain(t, r, c) // nothing new: nothing again
	if got := c.seen(); !slices.Equal(got, want) {
		t.Fatalf("seen %v, want %v (batches of 3 must not repeat or skip)", got, want)
	}
	insert(t, st, "decision", "late")
	catchUpTo(t, r, c, 9)
	if got := c.seen(); len(got) != 9 || got[8] != "late" {
		t.Fatalf("seen %v", got)
	}
}

// The reason for the xid horizon: a row whose transaction commits after a
// newer one must not be skipped, whatever the order of seq.
func TestARowThatCommitsLateIsNeverSkipped(t *testing.T) {
	st, r, c := setup(t)
	ctx := context.Background()

	slow, err := st.Pool().Begin(ctx) // an older transaction, still open
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slow.Rollback(ctx) }()
	if _, err := slow.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil { // takes its xid now
		t.Fatal(err)
	}
	insert(t, st, "decision", "fast") // newer xid, committed first, lower seq
	if _, err := slow.Exec(ctx, `INSERT INTO outbox (event_id, kind, occurred_at, payload) VALUES ('slow', 'decision', now(), '{}')`); err != nil {
		t.Fatal(err)
	}

	drain(t, r, c)
	if got := c.seen(); len(got) != 0 {
		t.Fatalf("seen %v while an older transaction is open: the consumer could not know about its row", got)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	catchUpTo(t, r, c, 2)
	got := c.seen()
	if !slices.Equal(got, []string{"slow", "fast"}) {
		t.Fatalf("seen %v, want both, in the order of their transactions", got)
	}
	drain(t, r, c)
	if len(c.seen()) != 2 {
		t.Fatal("a row was seen twice")
	}
}

func TestOnlyOneInstanceRunsAConsumer(t *testing.T) {
	st, r, _ := setup(t)
	insert(t, st, "decision", "x")
	waitFinal(t, st)
	blocker := &collector{name: "test", kinds: []string{"decision"}, enter: make(chan struct{}), release: make(chan struct{})}
	done := make(chan Cycle, 1)
	go func() {
		cy, _ := r.Step(context.Background(), blocker)
		done <- cy
	}()
	<-blocker.enter // the first instance is inside its turn

	other := &collector{name: "test", kinds: []string{"decision"}}
	cy, _ := r.Step(context.Background(), other)
	if !cy.Skipped || other.batches != 0 {
		t.Fatalf("a second instance ran the same consumer: %+v", cy)
	}
	close(blocker.release)
	if cy := <-done; cy.Err != nil || cy.Handled != 1 {
		t.Fatalf("first instance: %+v", cy)
	}
	// another consumer is independent
	if _, err := st.Pool().Exec(context.Background(), `INSERT INTO outbox_consumers (name) VALUES ('second')`); err != nil {
		t.Fatal(err)
	}
	second := &collector{name: "second", kinds: []string{"decision"}}
	if cy, _ := r.Step(context.Background(), second); cy.Skipped || cy.Handled != 1 {
		t.Fatalf("second consumer: %+v", cy)
	}
}

func TestAFailedTurnKeepsNeitherEffectsNorCursor(t *testing.T) {
	st, r, c := setup(t)
	insert(t, st, "decision", "a", "b")
	c.fail = errors.New("boom")
	cy, _ := r.Step(context.Background(), c)
	if cy.Err == nil {
		t.Fatal("handler error not reported")
	}
	var n int
	if err := st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM seen`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("effects of a failed turn kept: %d %v", n, err)
	}
	c.fail = nil
	catchUpTo(t, r, c, 2)
	if got := c.seen(); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("after the retry: %v", got)
	}
}

func TestOtherKindsAreSkippedAndTheCursorMovesOn(t *testing.T) {
	st, r, c := setup(t)
	insert(t, st, "usage", "u1", "u2", "u3", "u4", "u5")
	cy, _ := r.Step(context.Background(), c)
	if cy.Err != nil || cy.Handled != 0 || cy.Pending != 0 {
		t.Fatalf("cycle = %+v", cy)
	}
	var xid int64
	if err := st.Pool().QueryRow(context.Background(), `SELECT last_xid FROM outbox_consumers WHERE name='test'`).Scan(&xid); err != nil || xid == 0 {
		t.Fatalf("cursor stayed at the start (%d, %v): the rows of other kinds would be read again at every turn", xid, err)
	}
	insert(t, st, "decision", "d1")
	catchUpTo(t, r, c, 1)
	if got := c.seen(); !slices.Equal(got, []string{"d1"}) {
		t.Fatalf("seen %v", got)
	}
}

func TestPendingCountsWhatIsWaiting(t *testing.T) {
	st, r, c := setup(t)
	insert(t, st, "decision", "a", "b", "c", "d", "e")
	waitFinal(t, st)
	cy, more := r.Step(context.Background(), c) // batch size 3
	if !more || cy.Handled != 3 || cy.Pending != 2 {
		t.Fatalf("cycle = %+v more=%v", cy, more)
	}
}

func TestRunProcessesUntilStopped(t *testing.T) {
	st, r, c := setup(t)
	r.PollEvery = 10 * time.Millisecond
	var mu sync.Mutex
	cycles := 0
	r.OnCycle = func(Cycle) { mu.Lock(); cycles++; mu.Unlock() }
	insert(t, st, "decision", "a", "b", "c", "d")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(c.seen()) < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	insert(t, st, "decision", "e")
	for len(c.seen()) < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if got := c.seen(); len(got) != 5 {
		t.Fatalf("seen %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if cycles == 0 {
		t.Error("OnCycle never called")
	}
}

func TestAnUnregisteredConsumerIsAnError(t *testing.T) {
	_, r, _ := setup(t)
	ghost := &collector{name: "ghost", kinds: []string{"decision"}}
	if cy, _ := r.Step(context.Background(), ghost); cy.Err == nil {
		t.Fatal("no error for a consumer without a cursor")
	}
}

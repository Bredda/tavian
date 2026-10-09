package rollup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/quota"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

// These tests need a PostgreSQL: see internal/store/storetest.

type env struct {
	t      *testing.T
	st     *store.Store
	runner *outbox.Runner
	c      Consumer
	n      int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, _ := storetest.New(t)
	e := &env{t: t, st: st, c: Consumer{Log: slog.New(slog.DiscardHandler)}}
	e.runner = &outbox.Runner{Pool: st.Pool(), Log: slog.New(slog.DiscardHandler), BatchSize: 3}
	e.runner.Add(e.c)
	if err := e.runner.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

type ev map[string]any

func (e *env) usage(at time.Time, fields ev) {
	e.t.Helper()
	e.n++
	id := fmt.Sprintf("u-%d", e.n)
	base := ev{
		"event_id": id, "time": at.UTC().Format(time.RFC3339Nano), "key_id": "k1", "team": "finance", "application": "ledger",
		"model": "m", "backend": "local", "outcome": "ok", "input_tokens": 10, "output_tokens": 5, "cached_tokens": 0,
		"reasoning_tokens": 0, "usage_known": true,
	}
	for k, v := range fields {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	payload, _ := json.Marshal(base)
	if err := e.st.InsertOutbox(context.Background(), []store.OutboxRow{{EventID: id, Kind: "usage", OccurredAt: at, Payload: payload}}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) catchUp() {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		cy, _ := e.runner.Step(context.Background(), e.c)
		if cy.Err != nil {
			e.t.Fatal(cy.Err)
		}
		if cy.Pending == 0 && cy.Handled == 0 {
			var final, total int
			_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE xid < pg_snapshot_xmin(pg_current_snapshot())) FROM outbox`).Scan(&total, &final)
			if total == final {
				return
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatal("never caught up")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type row struct {
	requests, unknown, in, out, cached, reasoning int64
	cost                                          *int64
}

func (e *env) hourly(hour time.Time, team, principal string) (row, bool) {
	e.t.Helper()
	var r row
	err := e.st.Pool().QueryRow(context.Background(), `
SELECT requests, usage_unknown, input_tokens, output_tokens, cached_tokens, reasoning_tokens, cost_micro_eur
FROM usage_hourly WHERE hour = $1 AND team = $2 AND principal = $3`, hour, team, principal).
		Scan(&r.requests, &r.unknown, &r.in, &r.out, &r.cached, &r.reasoning, &r.cost)
	return r, err == nil
}

func hourOf(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }

func TestEventsAreSummedByTheHour(t *testing.T) {
	e := newEnv(t)
	h := time.Date(2026, 3, 10, 14, 0, 0, 0, time.UTC)
	e.usage(h.Add(5*time.Minute), ev{"input_tokens": 100, "output_tokens": 20, "cached_tokens": 7, "reasoning_tokens": 3})
	e.usage(h.Add(55*time.Minute), ev{"input_tokens": 1, "output_tokens": 2})
	e.usage(h.Add(61*time.Minute), ev{"input_tokens": 50, "output_tokens": 50}) // next hour
	e.usage(h.Add(10*time.Minute), ev{"key_id": nil, "user_id": "alice"})       // another principal
	e.usage(h.Add(10*time.Minute), ev{"usage_known": false, "input_tokens": 0, "output_tokens": 0, "outcome": "upstream_error"})
	e.catchUp()

	r, ok := e.hourly(h, "finance", "k1")
	if !ok || r.requests != 2 || r.in != 101 || r.out != 22 || r.cached != 7 || r.reasoning != 3 || r.unknown != 0 || r.cost != nil {
		t.Fatalf("hour 14 = %+v (%v)", r, ok)
	}
	if r, ok := e.hourly(h.Add(time.Hour), "finance", "k1"); !ok || r.requests != 1 || r.in != 50 {
		t.Fatalf("hour 15 = %+v", r)
	}
	if r, ok := e.hourly(h, "finance", "alice"); !ok || r.requests != 1 {
		t.Fatalf("a user is a principal of its own: %+v (%v)", r, ok)
	}
	var failed, unknown int64
	if err := e.st.Pool().QueryRow(context.Background(), `SELECT requests, usage_unknown FROM usage_hourly WHERE outcome = 'upstream_error'`).Scan(&failed, &unknown); err != nil || failed != 1 || unknown != 1 {
		t.Fatalf("failed requests: %d %d (%v)", failed, unknown, err)
	}
}

func TestEveryEventIsCountedOnce(t *testing.T) {
	e := newEnv(t)
	h := time.Now().UTC().Truncate(time.Hour)
	for i := 0; i < 10; i++ { // batches of 3
		e.usage(h.Add(time.Minute), nil)
	}
	e.catchUp()
	e.catchUp() // again: nothing new
	// a restart: a new consumer on the same cursor
	again := &outbox.Runner{Pool: e.st.Pool(), Log: slog.New(slog.DiscardHandler)}
	again.Add(Consumer{})
	again.Step(context.Background(), Consumer{})
	r, _ := e.hourly(h, "finance", "k1")
	if r.requests != 10 || r.in != 100 || r.out != 50 {
		t.Fatalf("sums = %+v, want 10 requests", r)
	}
	// an event that arrives late (a spool replay) goes to the hour it happened in
	e.usage(h.Add(-5*time.Hour), nil)
	e.catchUp()
	if r, ok := e.hourly(h.Add(-5*time.Hour), "finance", "k1"); !ok || r.requests != 1 {
		t.Fatalf("late event: %+v (%v)", r, ok)
	}
	if r, _ := e.hourly(h, "finance", "k1"); r.requests != 10 {
		t.Fatalf("the late event was added to the current hour: %+v", r)
	}
}

func TestCostIsSummedOnlyWhenThereIsOne(t *testing.T) {
	e := newEnv(t)
	h := time.Now().UTC().Truncate(time.Hour)
	e.usage(h, ev{"cost_micro_eur": 1500})
	e.usage(h, ev{"cost_micro_eur": 500})
	e.usage(h, ev{"model": "free"})
	e.catchUp()
	var withCost, free *int64
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT cost_micro_eur FROM usage_hourly WHERE model = 'm'`).Scan(&withCost)
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT cost_micro_eur FROM usage_hourly WHERE model = 'free'`).Scan(&free)
	if withCost == nil || *withCost != 2000 || free != nil {
		t.Fatalf("cost = %v / %v", withCost, free)
	}
}

func TestAnUnreadableEventDoesNotStopTheTotals(t *testing.T) {
	e := newEnv(t)
	h := time.Now().UTC().Truncate(time.Hour)
	e.usage(h, nil)
	if err := e.st.InsertOutbox(context.Background(), []store.OutboxRow{
		{EventID: "bad-json", Kind: "usage", OccurredAt: h, Payload: []byte(`{"time": 5}`)},
		{EventID: "no-time", Kind: "usage", OccurredAt: h, Payload: []byte(`{"team":"x"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	e.usage(h, nil)
	e.catchUp()
	if r, _ := e.hourly(h, "finance", "k1"); r.requests != 2 {
		t.Fatalf("sums = %+v", r)
	}
}

func total(used []TeamApp) int64 {
	var n int64
	for _, u := range used {
		n += u.Tokens
	}
	return n
}

// Tokens used today are the hourly sums plus what the rollup has not reached,
// each event once.
func TestTokensTodayAreTheRolledUpSumsPlusTheTail(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	e.usage(startOfDay.Add(-time.Hour), ev{"input_tokens": 1000, "output_tokens": 1000}) // yesterday
	e.usage(startOfDay.Add(time.Minute), ev{"input_tokens": 10, "output_tokens": 5})
	e.usage(startOfDay.Add(time.Minute), ev{"team": "research", "application": "chat", "input_tokens": 7, "output_tokens": 3})
	e.catchUp()                                                // these are rolled up
	e.usage(now, ev{"input_tokens": 100, "output_tokens": 50}) // not yet
	e.usage(now, ev{"team": "research", "application": "chat", "input_tokens": 1, "output_tokens": 1})
	waitFinal(t, e.st)

	used, err := TokensToday(context.Background(), e.st.Pool(), now)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int64{}
	for _, u := range used {
		by[u.Team+"/"+u.Application] = u.Tokens
	}
	if by["finance/ledger"] != 165 || by["research/chat"] != 12 || total(used) != 177 {
		t.Fatalf("used = %v, want finance 165 (15 rolled + 150 in the tail), research 12, and nothing from yesterday", by)
	}
	e.catchUp() // once rolled up, the same totals
	used, _ = TokensToday(context.Background(), e.st.Pool(), now)
	if total(used) != 177 {
		t.Fatalf("after the rollup caught up: %d, an event was counted twice or lost", total(used))
	}
}

func waitFinal(t *testing.T, st *store.Store) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var total, final int
		_ = st.Pool().QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE xid < pg_snapshot_xmin(pg_current_snapshot())) FROM outbox`).Scan(&total, &final)
		if total == final {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("horizon never passed")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestTokensTodayWithoutARollupConsumerCountsEverything(t *testing.T) {
	st, _ := storetest.New(t) // no consumer registered, as on the first start after an upgrade
	e := &env{t: t, st: st}
	e.usage(time.Now(), ev{"input_tokens": 10, "output_tokens": 5})
	used, err := TokensToday(context.Background(), st.Pool(), time.Now())
	if err != nil || total(used) != 15 {
		t.Fatalf("used = %v (%v)", used, err)
	}
}

func TestSeedGivesScopesTheirUsage(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	e.usage(now, ev{"input_tokens": 10, "output_tokens": 5})
	e.usage(now, ev{"team": "research", "application": "chat", "input_tokens": 100, "output_tokens": 0})
	e.usage(now, ev{"team": "finance", "application": "reports", "input_tokens": 1000, "output_tokens": 0})
	waitFinal(t, e.st)

	store := quota.NewStore(nil)
	scopes := []quota.Scope{
		{Organization: true}, {Team: "finance"}, {Application: "chat"}, {Team: "finance", Application: "ledger"}, {Team: "nobody"},
	}
	n, err := Seed(context.Background(), e.st.Pool(), store, scopes, now)
	if err != nil || n != len(scopes) {
		t.Fatalf("seeded %d of %d (%v)", n, len(scopes), err)
	}
	want := map[quota.Scope]int64{
		{Organization: true}: 1115, {Team: "finance"}: 1015, {Application: "chat"}: 100,
		{Team: "finance", Application: "ledger"}: 15, {Team: "nobody"}: 0,
	}
	for scope, tokens := range want {
		// holds at least `tokens`: one more does not fit under a limit of tokens...
		tight := []quota.Limit{{Policy: "p", Scope: scope, Dimension: quota.TokensPerDay, Max: tokens}}
		if _, res := store.Reserve(tight, 1); !res.Refused {
			t.Errorf("%+v: the counter holds less than %d", scope, tokens)
		}
		// ...and at most that: one more fits under tokens+1
		loose := []quota.Limit{{Policy: "p", Scope: scope, Dimension: quota.TokensPerDay, Max: tokens + 1}}
		if _, res := store.Reserve(loose, 1); res.Refused {
			t.Errorf("%+v: the counter holds more than %d", scope, tokens)
		}
	}
	// a counter that already counts is left alone
	if n, _ := Seed(context.Background(), e.st.Pool(), store, scopes, now); n != 0 {
		t.Errorf("seeded %d counters that existed", n)
	}
	if n, err := Seed(context.Background(), e.st.Pool(), store, nil, now); n != 0 || err != nil {
		t.Errorf("no scopes: %d %v", n, err)
	}
}

func TestSeededDayRollsOverLikeAnyOther(t *testing.T) {
	e := newEnv(t)
	clk := time.Now()
	store := quota.NewStore(func() time.Time { return clk })
	e.usage(clk, ev{"input_tokens": 90, "output_tokens": 0})
	waitFinal(t, e.st)
	scope := quota.Scope{Team: "finance"}
	if _, err := Seed(context.Background(), e.st.Pool(), store, []quota.Scope{scope}, clk); err != nil {
		t.Fatal(err)
	}
	lim := []quota.Limit{{Policy: "p", Scope: scope, Dimension: quota.TokensPerDay, Max: 100}}
	if _, res := store.Reserve(lim, 20); !res.Refused {
		t.Fatal("seeded usage ignored")
	}
	clk = clk.Add(25 * time.Hour)
	if _, res := store.Reserve(lim, 100); res.Refused {
		t.Fatal("seeded usage survived the day")
	}
}

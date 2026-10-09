package quota

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var team = Scope{Team: "finance"}

func lim(d Dimension, max int64) Limit {
	return Limit{Policy: "p", Scope: team, Dimension: d, Max: max}
}

func TestRPMSlidingWindow(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(RPM, 3)}
	for i := 0; i < 3; i++ {
		if _, res := s.Admit(limits); res.Refused {
			t.Fatalf("request %d refused", i)
		}
		clk.advance(10 * time.Second)
	}
	// 30 s in: three requests in the last minute
	_, res := s.Admit(limits)
	if !res.Refused {
		t.Fatal("fourth request in a minute was admitted")
	}
	if got := res.Primary().Retry; got != 30*time.Second {
		t.Fatalf("retry = %v, want 30s (the first request leaves the window then)", got)
	}
	clk.advance(30 * time.Second) // the first request is now a minute old
	if _, res := s.Admit(limits); res.Refused {
		t.Fatal("still refused after the oldest request left the window")
	}
}

func TestRefusedRequestsAreNotCounted(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(RPM, 1)}
	s.Admit(limits)
	for i := 0; i < 50; i++ {
		s.Admit(limits) // refused
	}
	clk.advance(61 * time.Second)
	if _, res := s.Admit(limits); res.Refused {
		t.Fatal("refusals extended their own penalty")
	}
}

func TestConcurrencyIsHeldUntilRelease(t *testing.T) {
	s := NewStore(nil)
	limits := []Limit{lim(Concurrency, 2)}
	a, _ := s.Admit(limits)
	b, _ := s.Admit(limits)
	if _, res := s.Admit(limits); !res.Refused {
		t.Fatal("third concurrent request admitted")
	}
	a.Release()
	a.Release() // harmless
	c, res := s.Admit(limits)
	if res.Refused {
		t.Fatal("slot not given back by Release")
	}
	if _, res := s.Admit(limits); !res.Refused {
		t.Fatal("a double Release gave back two slots")
	}
	b.Release()
	c.Release()
	var nilSlot *Slot
	nilSlot.Release()
}

func TestAdmitIsAllOrNothing(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	org := Limit{Policy: "o", Scope: Scope{Organization: true}, Dimension: RPM, Max: 100}
	strict := lim(RPM, 1)
	conc := lim(Concurrency, 5)
	limits := []Limit{org, strict, conc}
	slot, res := s.Admit(limits)
	if res.Refused {
		t.Fatal("first request refused")
	}
	slot.Release()
	if _, res := s.Admit(limits); !res.Refused {
		t.Fatal("team rpm not enforced")
	}
	// the refused request must not have counted against the org or the team
	// concurrency; only the first request is in the org's minute
	orgOnly := []Limit{{Policy: "o", Scope: Scope{Organization: true}, Dimension: RPM, Max: 2}}
	if _, res := s.Admit(orgOnly); res.Refused {
		t.Fatal("org counted the refused request")
	}
	if _, res := s.Admit(orgOnly); !res.Refused {
		t.Fatal("org counter lost the admitted requests")
	}
}

func TestTwoPoliciesOnOneCounterCountOnce(t *testing.T) {
	s := NewStore(nil)
	a := Limit{Policy: "a", Scope: team, Dimension: RPM, Max: 3}
	b := Limit{Policy: "b", Scope: team, Dimension: RPM, Max: 10}
	s.Admit([]Limit{a, b})
	s.Admit([]Limit{a, b})
	// two requests counted once each: the third fits under a's 3
	if _, res := s.Admit([]Limit{a}); res.Refused {
		t.Fatal("a request was counted once per policy that limits it (admit)")
	}

	tp := Limit{Policy: "a", Scope: team, Dimension: TPM, Max: 300}
	td := Limit{Policy: "b", Scope: team, Dimension: TPM, Max: 10000}
	s.Reserve([]Limit{tp, td}, Tokens(100))
	s.Reserve([]Limit{tp, td}, Tokens(100))
	if _, res := s.Reserve([]Limit{tp}, Tokens(100)); res.Refused {
		t.Fatal("tokens were counted once per policy that limits them (reserve)")
	}
	if _, res := s.Reserve([]Limit{tp}, Tokens(1)); !res.Refused {
		t.Fatal("tokens were not counted")
	}
}

func TestSoftAndShadowLimitsNeverRefuse(t *testing.T) {
	s := NewStore(nil)
	soft := lim(RPM, 1)
	soft.Soft = true
	shadow := Limit{Policy: "s", Scope: Scope{Application: "x"}, Dimension: RPM, Max: 1, Shadow: true}
	limits := []Limit{soft, shadow}
	s.Admit(limits)
	_, res := s.Admit(limits)
	if res.Refused {
		t.Fatal("soft or shadow limit refused")
	}
	if len(res.Exceeded) != 2 {
		t.Fatalf("exceeded = %d, want both reported", len(res.Exceeded))
	}
	if res.Primary() != nil {
		t.Fatal("a request that was not refused has a primary check")
	}
	if got := []string{res.Exceeded[0].Limit.Effect(), res.Exceeded[1].Limit.Effect()}; got[0] != "soft" || got[1] != "shadow" {
		t.Fatalf("effects = %v", got)
	}
}

func TestReserveAndSettleTPM(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(TPM, 1000)}
	r, res := s.Reserve(limits, Tokens(800))
	if res.Refused || r.Tokens() != 800 {
		t.Fatalf("reserve 800 of 1000 failed: %+v", res)
	}
	if _, res := s.Reserve(limits, Tokens(300)); !res.Refused {
		t.Fatal("reservations did not add up")
	}
	r.Settle(Tokens(100)) // the answer was short: 700 come back
	r2, res := s.Reserve(limits, Tokens(800))
	if res.Refused {
		t.Fatal("settle did not return the unused reservation")
	}
	r2.Settle(Tokens(800))
	r.Settle(Tokens(5000)) // second settle is ignored
	if _, res := s.Reserve(limits, Tokens(101)); !res.Refused {
		t.Fatal("window should hold 100 + 800 now")
	}
	if _, res := s.Reserve(limits, Tokens(100)); res.Refused {
		t.Fatal("a second Settle changed the count")
	}
}

func TestSettleCanOverdraw(t *testing.T) {
	s := NewStore(nil)
	limits := []Limit{lim(TokensPerDay, 1000)}
	r, _ := s.Reserve(limits, Tokens(100))
	r.Settle(Tokens(5000)) // far more than reserved: owed
	_, res := s.Reserve(limits, Tokens(1))
	if !res.Refused {
		t.Fatal("tokens already produced were forgiven")
	}
	if res.Primary().Used != 5000 {
		t.Fatalf("used = %d, want 5000", res.Primary().Used)
	}
}

func TestSettleAfterTheWindowMoved(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(TPM, 1000)}
	r, _ := s.Reserve(limits, Tokens(600))
	clk.advance(3 * time.Minute) // a long stream: the reservation left the window
	r.Settle(Tokens(400))
	if _, res := s.Reserve(limits, Tokens(700)); !res.Refused {
		t.Fatal("tokens used by a long answer were lost when their reservation expired")
	}
	if _, res := s.Reserve(limits, Tokens(600)); res.Refused {
		t.Fatal("expired reservation was charged twice")
	}
}

func TestSettleNeverGoesBelowZero(t *testing.T) {
	s := NewStore(nil)
	limits := []Limit{lim(TPM, 10), lim(TokensPerDay, 10)}
	r, _ := s.Reserve(limits, Tokens(5))
	r.Settle(Tokens(0))
	r2, res := s.Reserve(limits, Tokens(10))
	if res.Refused {
		t.Fatal("refund left a debt behind")
	}
	r2.Settle(Tokens(-7)) // a faulty caller
	if _, res := s.Reserve(limits, Tokens(10)); res.Refused {
		t.Fatal("negative settle was not clamped")
	}
}

func TestDayRollsOverAtMidnightUTC(t *testing.T) {
	clk := newClock() // 12:00 UTC
	s := NewStore(clk.now)
	limits := []Limit{lim(TokensPerDay, 1000)}
	r, _ := s.Reserve(limits, Tokens(1000))
	r.Settle(Tokens(1000))
	_, res := s.Reserve(limits, Tokens(1))
	if !res.Refused {
		t.Fatal("daily limit not enforced")
	}
	if got := res.Primary().Retry; got != 12*time.Hour {
		t.Fatalf("retry = %v, want 12h until midnight UTC", got)
	}
	clk.advance(12 * time.Hour)
	if _, res := s.Reserve(limits, Tokens(1000)); res.Refused {
		t.Fatal("counter not reset at midnight UTC")
	}
}

func TestSettleAcrossMidnightCountsOnTheNewDay(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(TokensPerDay, 1000)}
	r, _ := s.Reserve(limits, Tokens(900))
	clk.advance(13 * time.Hour)
	r.Settle(Tokens(200))
	if _, res := s.Reserve(limits, Tokens(801)); !res.Refused {
		t.Fatal("tokens of a request that ended after midnight were not counted")
	}
	if _, res := s.Reserve(limits, Tokens(800)); res.Refused {
		t.Fatal("the reservation of the previous day leaked into the new one")
	}
}

func TestARequestThatCanNeverFit(t *testing.T) {
	s := NewStore(nil)
	for _, d := range []Dimension{TPM, TokensPerDay} {
		_, res := s.Reserve([]Limit{lim(d, 100)}, Tokens(101))
		p := res.Primary()
		if p == nil || !p.Never || p.Retry != 0 {
			t.Fatalf("%s: a request larger than the limit must say waiting will not help: %+v", d, p)
		}
	}
}

func TestReserveIsAllOrNothing(t *testing.T) {
	s := NewStore(nil)
	big := Limit{Policy: "o", Scope: Scope{Organization: true}, Dimension: TPM, Max: 10000}
	small := lim(TPM, 100)
	if _, res := s.Reserve([]Limit{big, small}, Tokens(500)); !res.Refused {
		t.Fatal("small limit ignored")
	}
	// nothing may have been counted against the org
	if _, res := s.Reserve([]Limit{big}, Tokens(10000)); res.Refused {
		t.Fatal("a refused reservation was counted against another scope")
	}
}

func TestOnlyTheRightDimensionsAreChecked(t *testing.T) {
	s := NewStore(nil)
	if slot, res := s.Admit([]Limit{lim(TPM, 1)}); slot != nil || res.Refused {
		t.Fatal("Admit looked at a token limit")
	}
	if r, res := s.Reserve([]Limit{lim(RPM, 1), lim(Concurrency, 1)}, Tokens(1<<20)); r != nil || res.Refused {
		t.Fatal("Reserve looked at an admission limit")
	}
	var nilRes *Reservation
	nilRes.Settle(Tokens(5))
	if nilRes.Tokens() != 0 {
		t.Fatal("nil reservation has tokens")
	}
}

// Under concurrency exactly the limit is admitted, never more: the check and
// the count are one step.
func TestConcurrentAdmissionNeverExceedsTheLimit(t *testing.T) {
	const limit, callers = 50, 400
	s := NewStore(nil)
	limits := []Limit{lim(RPM, limit), lim(Concurrency, limit)}
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if slot, res := s.Admit(limits); !res.Refused {
				admitted.Add(1)
				_ = slot // held: concurrency never gets released in this test
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != limit {
		t.Fatalf("admitted %d, want exactly %d", admitted.Load(), limit)
	}
}

func TestConcurrentReservationsNeverExceedTheLimit(t *testing.T) {
	const limit, per, callers = 10000, 100, 400
	s := NewStore(nil)
	limits := []Limit{lim(TPM, limit), lim(TokensPerDay, limit)}
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, res := s.Reserve(limits, Tokens(per)); !res.Refused {
				admitted.Add(1)
				r.Settle(Tokens(per))
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != limit/per {
		t.Fatalf("admitted %d requests of %d tokens, want exactly %d", admitted.Load(), per, limit/per)
	}
}

func TestEstimateIsConservative(t *testing.T) {
	// English runs at about four bytes a token, CJK at three: three is never low
	if got := Estimate(3000, 0); got < 1000 {
		t.Fatalf("estimate for 3000 bytes = %d, want at least 1000", got)
	}
	if got := Estimate(0, 500); got < 500 {
		t.Fatalf("the answer cap is missing from the estimate: %d", got)
	}
	if got := Estimate(10, 1<<62); got <= 0 {
		t.Fatalf("a huge max_tokens overflowed the estimate: %d", got)
	}
	if got := Estimate(10, -5); got < 0 {
		t.Fatalf("negative max_tokens: %d", got)
	}
}

func TestCoalescerRecordsOncePerSecondPerCaller(t *testing.T) {
	clk := newClock()
	c := NewCoalescer(clk.now)
	rec, sup := c.Allow(team, RPM, "key-a")
	if !rec || sup != 0 {
		t.Fatal("first refusal must be recorded")
	}
	for i := 0; i < 5; i++ {
		if rec, _ := c.Allow(team, RPM, "key-a"); rec {
			t.Fatal("refusal within the second recorded again")
		}
	}
	if rec, _ := c.Allow(team, RPM, "key-b"); !rec {
		t.Fatal("another caller's refusal was hidden by key-a's")
	}
	if rec, _ := c.Allow(team, TPM, "key-a"); !rec {
		t.Fatal("another limit's refusal was hidden")
	}
	clk.advance(time.Second)
	rec, sup = c.Allow(team, RPM, "key-a")
	if !rec || sup != 5 {
		t.Fatalf("after a second: recorded=%v suppressed=%d, want true and 5", rec, sup)
	}
}

func TestCoalescerStaysBoundedAndFailsTowardRecording(t *testing.T) {
	clk := newClock()
	c := NewCoalescer(clk.now)
	for i := 0; i < maxCoalesced+500; i++ {
		rec, _ := c.Allow(team, RPM, string(rune('a'+i%26))+time.Duration(i).String())
		if !rec {
			t.Fatalf("a first refusal of caller %d was not recorded", i)
		}
	}
	if len(c.entries) > maxCoalesced {
		t.Fatalf("%d entries kept, want at most %d", len(c.entries), maxCoalesced)
	}
	clk.advance(2 * time.Second)
	if rec, _ := c.Allow(team, RPM, "late"); !rec {
		t.Fatal("not recorded")
	}
	if len(c.entries) >= maxCoalesced {
		t.Fatal("stale entries were not swept")
	}
}

func TestScopeMatches(t *testing.T) {
	for _, c := range []struct {
		scope     Scope
		team, app string
		want      bool
	}{
		{Scope{Organization: true}, "a", "b", true},
		{Scope{Team: "a"}, "a", "b", true},
		{Scope{Team: "a"}, "x", "b", false},
		{Scope{Application: "b"}, "x", "b", true},
		{Scope{Application: "b"}, "x", "y", false},
		{Scope{Team: "a", Application: "b"}, "a", "b", true},
		{Scope{Team: "a", Application: "b"}, "a", "y", false},
		{Scope{Team: "a", Application: "b"}, "x", "b", false},
	} {
		if got := c.scope.Matches(c.team, c.app); got != c.want {
			t.Errorf("%+v.Matches(%q, %q) = %v", c.scope, c.team, c.app, got)
		}
	}
}

func TestSeedTokensPerDay(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	limits := []Limit{lim(TokensPerDay, 1000)}
	if !s.SeedTokensPerDay(team, 900) {
		t.Fatal("not seeded")
	}
	if s.SeedTokensPerDay(team, 5) {
		t.Fatal("a counter that exists was seeded again")
	}
	if _, res := s.Reserve(limits, Tokens(101)); !res.Refused {
		t.Fatal("seeded tokens not counted")
	}
	r, res := s.Reserve(limits, Tokens(100))
	if res.Refused {
		t.Fatal("seeded more than 900")
	}
	r.Settle(Tokens(100))
	// a counter that was counting is not overwritten
	other := Scope{Team: "other"}
	if _, res := s.Reserve([]Limit{{Policy: "p", Scope: other, Dimension: TokensPerDay, Max: 100}}, Tokens(10)); res.Refused {
		t.Fatal("setup")
	}
	if s.SeedTokensPerDay(other, 99) {
		t.Fatal("a counter in use was overwritten")
	}
	s.SeedTokensPerDay(Scope{Team: "neg"}, -50)
	if _, res := s.Reserve([]Limit{{Policy: "p", Scope: Scope{Team: "neg"}, Dimension: TokensPerDay, Max: 10}}, Tokens(10)); res.Refused {
		t.Fatal("a negative seed became a debt")
	}
	// the seed belongs to today
	clk.advance(24 * time.Hour)
	if _, res := s.Reserve(limits, Tokens(1000)); res.Refused {
		t.Fatal("seeded tokens survived midnight")
	}
}

func TestBudgetIsReservedAndSettledInMoney(t *testing.T) {
	s := NewStore(nil)
	budget := []Limit{lim(BudgetEUR, 1_000_000)} // 1 EUR
	r, res := s.Reserve(budget, Amount{Tokens: 999999999, MicroEUR: 600_000})
	if res.Refused {
		t.Fatal("0.60 EUR of 1 EUR refused: the tokens must not count against a budget")
	}
	if r.MicroEUR() != 600_000 || r.Tokens() != 999999999 {
		t.Fatalf("reserved %d tokens, %d micro-EUR", r.Tokens(), r.MicroEUR())
	}
	if _, res := s.Reserve(budget, Amount{MicroEUR: 500_000}); !res.Refused {
		t.Fatal("reservations in money did not add up")
	}
	r.Settle(Amount{MicroEUR: 100_000}) // the answer was cheap
	if _, res := s.Reserve(budget, Amount{MicroEUR: 900_000}); res.Refused {
		t.Fatal("settle did not return the unused part")
	}
	r.Settle(Amount{MicroEUR: 5_000_000}) // second settle ignored
	if _, res := s.Reserve(budget, Amount{MicroEUR: 1}); !res.Refused {
		t.Fatal("0.10 + 0.90 should have used the whole budget")
	}
}

func TestMoneyDoesNotCountAgainstTokenLimitsEither(t *testing.T) {
	s := NewStore(nil)
	tokens := []Limit{lim(TPM, 100), lim(TokensPerDay, 100)}
	if _, res := s.Reserve(tokens, Amount{Tokens: 50, MicroEUR: 999_999_999}); res.Refused {
		t.Fatal("money counted as tokens")
	}
}

func TestBudgetOverrunIsOwed(t *testing.T) {
	s := NewStore(nil)
	budget := []Limit{lim(BudgetEUR, 1000)}
	r, _ := s.Reserve(budget, Amount{MicroEUR: 100})
	r.Settle(Amount{MicroEUR: 5000})
	_, res := s.Reserve(budget, Amount{MicroEUR: 1})
	if !res.Refused || res.Primary().Used != 5000 {
		t.Fatalf("the overrun was forgiven: %+v", res.Primary())
	}
}

func TestBudgetRollsOverOnTheFirstOfTheMonthUTC(t *testing.T) {
	clk := newClock() // 2026-03-10 12:00 UTC
	s := NewStore(clk.now)
	budget := []Limit{lim(BudgetEUR, 1000)}
	r, _ := s.Reserve(budget, Amount{MicroEUR: 1000})
	r.Settle(Amount{MicroEUR: 1000})
	_, res := s.Reserve(budget, Amount{MicroEUR: 1})
	if !res.Refused {
		t.Fatal("budget not enforced")
	}
	// from 10 March 12:00 to 1 April 00:00
	if got, want := res.Primary().Retry, 21*24*time.Hour+12*time.Hour; got != want {
		t.Fatalf("retry = %v, want %v", got, want)
	}
	if res.Primary().Never {
		t.Fatal("a spent month is not a request that can never fit")
	}
	clk.advance(21*24*time.Hour + 12*time.Hour)
	if _, res := s.Reserve(budget, Amount{MicroEUR: 1000}); res.Refused {
		t.Fatal("budget not reset on the 1st")
	}
}

func TestBudgetSettleAcrossTheMonthEnd(t *testing.T) {
	clk := newClock()
	clk.t = time.Date(2026, 3, 31, 23, 0, 0, 0, time.UTC)
	s := NewStore(clk.now)
	budget := []Limit{lim(BudgetEUR, 1000)}
	r, _ := s.Reserve(budget, Amount{MicroEUR: 900})
	clk.advance(2 * time.Hour) // April
	r.Settle(Amount{MicroEUR: 200})
	if _, res := s.Reserve(budget, Amount{MicroEUR: 801}); !res.Refused {
		t.Fatal("what a request used after midnight was not counted")
	}
	if _, res := s.Reserve(budget, Amount{MicroEUR: 800}); res.Refused {
		t.Fatal("March's reservation leaked into April")
	}
}

func TestBudgetMonthsAreNotConfusedAcrossYears(t *testing.T) {
	a := time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC)
	for _, b := range []time.Time{time.Date(2027, 12, 15, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)} {
		if monthOf(a) == monthOf(b) {
			t.Errorf("%v and %v are the same month", a, b)
		}
	}
	if monthOf(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)) != monthOf(a) {
		t.Error("two days of December are different months")
	}
	if got := untilNextMonth(time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)); got != time.Hour {
		t.Errorf("until January = %v", got)
	}
}

func TestBudgetThatCanNeverFit(t *testing.T) {
	s := NewStore(nil)
	_, res := s.Reserve([]Limit{lim(BudgetEUR, 100)}, Amount{MicroEUR: 101})
	if p := res.Primary(); p == nil || !p.Never || p.Retry != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestSeedBudget(t *testing.T) {
	clk := newClock()
	s := NewStore(clk.now)
	if !s.SeedBudget(team, 900) || s.SeedBudget(team, 1) {
		t.Fatal("seed once")
	}
	budget := []Limit{lim(BudgetEUR, 1000)}
	if _, res := s.Reserve(budget, Amount{MicroEUR: 101}); !res.Refused {
		t.Fatal("seed ignored")
	}
	if _, res := s.Reserve(budget, Amount{MicroEUR: 100}); res.Refused {
		t.Fatal("seeded too much")
	}
	s.SeedBudget(Scope{Team: "neg"}, -5)
	if _, res := s.Reserve([]Limit{{Policy: "p", Scope: Scope{Team: "neg"}, Dimension: BudgetEUR, Max: 10}}, Amount{MicroEUR: 10}); res.Refused {
		t.Fatal("negative seed became a debt")
	}
	clk.advance(30 * 24 * time.Hour)
	if _, res := s.Reserve(budget, Amount{MicroEUR: 1000}); res.Refused {
		t.Fatal("seed survived the month")
	}
}

func TestBudgetIsAReservationDimension(t *testing.T) {
	s := NewStore(nil)
	if slot, res := s.Admit([]Limit{lim(BudgetEUR, 1)}); slot != nil || res.Refused {
		t.Fatal("Admit looked at the budget")
	}
	if BudgetEUR.Window() != "month" || !BudgetEUR.Valid() {
		t.Fatal("budget_eur description")
	}
}

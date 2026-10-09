package server

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/cost"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/quota"
)

func ptr[T any](v T) *T { return &v }

// priced gives the routes of the fixture a price and an energy profile, and the
// local backend a carbon intensity.
func priced(input, output float64) func(*config.Snapshot) {
	return func(s *config.Snapshot) {
		for _, m := range s.Models {
			for i := range m.Route {
				m.Route[i].Price = &cost.Price{Input: input, Output: output}
				m.Route[i].Energy = &cost.Energy{WhPer1KInput: 10, WhPer1KOutput: 20, Method: cost.MethodEstimated, Confidence: cost.ConfidenceLow}
			}
		}
		s.Backends["local"].CarbonGPerKWh = ptr(100.0)
		s.Backends["local"].Region = "fr-par"
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCostEnergyAndCarbonAreInTheUsageEventTheRecordAndTheMetrics(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, snap: priced(1000, 2000)})
	if resp := f.post(t, f.key, chatBody); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	evs := f.sink.Events()
	if len(evs) != 1 {
		t.Fatalf("%d usage events", len(evs))
	}
	ev := evs[0]
	in, out := float64(ev.InputTokens), float64(ev.OutputTokens)
	if in == 0 || out == 0 || !ev.UsageKnown {
		t.Fatalf("setup: the mock reported %d in, %d out", ev.InputTokens, ev.OutputTokens)
	}
	wantCost := int64(math.Round(in*1000 + out*2000))
	wantWh := in/1000*10 + out/1000*20
	if ev.CostMicroEUR == nil || *ev.CostMicroEUR != wantCost {
		t.Fatalf("cost = %v, want %d", ev.CostMicroEUR, wantCost)
	}
	if ev.EnergyWh == nil || !near(*ev.EnergyWh, wantWh) || ev.CO2eGrams == nil || !near(*ev.CO2eGrams, wantWh/1000*100) {
		t.Fatalf("energy %v carbon %v, want %g Wh and %g g", ev.EnergyWh, ev.CO2eGrams, wantWh, wantWh/10)
	}
	b := ev.Basis
	if b == nil || *b.PriceInputPer1MEUR != 1000 || *b.PriceOutputPer1MEUR != 2000 || *b.WhPer1KInput != 10 || *b.WhPer1KOutput != 20 ||
		b.EnergyMethod != "estimated" || b.EnergyConfidence != "low" || b.Region != "fr-par" || *b.CarbonGPerKWh != 100 || !b.Estimate {
		t.Errorf("basis = %+v", b)
	}

	d := lastDecision(t, f)
	if d.Cost == nil || d.Cost.MicroEUR == nil || *d.Cost.MicroEUR != wantCost || d.Cost.EnergyWh == nil || d.Cost.CO2eGrams == nil || !d.Cost.Estimate {
		t.Errorf("decision record cost = %+v", d.Cost)
	}
	m := metricsText(t, f)
	for _, want := range []string{
		fmt.Sprintf(`tavian_cost_total{backend="local",model="llama-70b",unit="micro_eur"} %d`, wantCost),
		`tavian_cost_total{backend="local",model="llama-70b",unit="energy_wh"}`,
		`tavian_cost_total{backend="local",model="llama-70b",unit="co2e_grams"}`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestNothingIsPricedWhenNothingIsConfigured(t *testing.T) {
	f := newFixture(t, 0)
	f.post(t, f.key, chatBody)
	ev := f.sink.Events()[0]
	if ev.CostMicroEUR != nil || ev.EnergyWh != nil || ev.CO2eGrams != nil || ev.Basis != nil {
		t.Errorf("event = %+v", ev)
	}
	if d := lastDecision(t, f); d.Cost != nil {
		t.Errorf("cost = %+v", d.Cost)
	}
	if strings.Contains(metricsText(t, f), "tavian_cost_total{") {
		t.Error("cost metrics without prices")
	}
}

func TestNoCostIsMadeUpWhenTheBackendReportsNoUsage(t *testing.T) {
	silent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	})
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, backend: silent, snap: priced(1000, 2000)})
	if resp := f.post(t, f.key, chatBody); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ev := f.sink.Events()[0]
	if ev.UsageKnown || ev.CostMicroEUR != nil || ev.EnergyWh != nil || ev.Basis != nil {
		t.Errorf("event = %+v: nothing was reported, nothing is priced", ev)
	}
	if d := lastDecision(t, f); d.Cost != nil {
		t.Errorf("cost = %+v", d.Cost)
	}
}

func TestACostIsOnlyAsGoodAsTheEnergyProfileAndIntensity(t *testing.T) {
	f := buildFixture(t, fixtureSpec{maxBody: 1 << 20, snap: func(s *config.Snapshot) {
		for _, m := range s.Models {
			for i := range m.Route {
				m.Route[i].Energy = &cost.Energy{WhPer1KInput: 10, WhPer1KOutput: 20, Method: cost.MethodMeasured, Confidence: cost.ConfidenceHigh}
			}
		}
	}})
	f.post(t, f.key, chatBody)
	ev := f.sink.Events()[0]
	if ev.CostMicroEUR != nil || ev.EnergyWh == nil || ev.CO2eGrams != nil {
		t.Errorf("energy without a price or an intensity: cost %v energy %v carbon %v", ev.CostMicroEUR, ev.EnergyWh, ev.CO2eGrams)
	}
}

// budgetGateway is a gateway with prices of 100000 EUR per million tokens (0.10
// EUR a token), so that a few requests spend a few euros.
func budgetGateway(t *testing.T, budgetEUR int, snap func(*config.Snapshot)) *quotaFixture {
	t.Helper()
	q := &quotaFixture{store: newClock(), refusals: newClock()}
	if snap == nil {
		snap = priced(100000, 100000)
	}
	q.fixture = buildFixture(t, fixtureSpec{
		maxBody: 1 << 20, snap: snap,
		policies: []policy.Source{quotaPolicy("monthly", "{ team: research }", "enforce", fmt.Sprintf("[ { dimension: budget_eur, limit: %d } ]", budgetEUR))},
		deps: []func(*Deps){func(d *Deps) {
			d.Quota = quota.NewStore(q.store.now)
			d.Coalescer = quota.NewCoalescer(q.refusals.now)
		}},
	})
	return q
}

const smallChat = `{"model":"llama-70b","max_tokens":5,"messages":[{"role":"user","content":"hello there world"}]}`

func TestTheMonthlyBudgetRunsOutAfterWhatWasReallySpent(t *testing.T) {
	// a request reserves about 3.5 EUR and spends under 1: the settle gives
	// the difference back, so far more than three requests fit in 10 EUR
	q := budgetGateway(t, 10, nil)
	served := 0
	var last *http.Response
	for i := 0; i < 40; i++ {
		last = q.post(t, q.key, smallChat)
		if last.StatusCode != 200 {
			break
		}
		served++
	}
	if served < 5 || served > 20 || last.StatusCode != 429 {
		t.Fatalf("served %d requests, then status %d", served, last.StatusCode)
	}
	e := readError(t, last)
	if e.Code != "quota_exceeded" || !strings.Contains(e.Message, "euros per month") || !strings.Contains(e.Message, "10") {
		t.Errorf("error = %+v: SDKs must not retry an empty month, and the limit is in euros", e)
	}
	if got := last.Header.Get("Retry-After"); got != "1857600" { // 10 March 12:00 to 1 April 00:00 = 21.5 days
		t.Errorf("Retry-After = %q", got)
	}
	d := lastDecision(t, q.fixture)
	if d.ReasonCode != "QUOTA_EXCEEDED" || d.Quota == nil || d.Quota.Exceeded[0].Dimension != "budget_eur" || d.Quota.Exceeded[0].Limit != 10_000_000 {
		t.Errorf("record = %s %+v", d.ReasonCode, d.Quota)
	}
	q.store.advance(21*24*time.Hour + 12*time.Hour)
	if resp := q.post(t, q.key, smallChat); resp.StatusCode != 200 {
		t.Errorf("on the 1st: status %d", resp.StatusCode)
	}
}

func TestTheRecordShowsWhatWasReservedInMoney(t *testing.T) {
	q := budgetGateway(t, 1000, nil)
	if resp := q.post(t, q.key, smallChat); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	d := lastDecision(t, q.fixture)
	// about 25 request tokens and 5 of answer at 0.10 EUR
	if d.Quota == nil || d.Quota.ReservedMicroEUR < 2_000_000 || d.Quota.ReservedMicroEUR > 6_000_000 {
		t.Errorf("reserved = %+v", d.Quota)
	}
}

func TestARequestDearerThanTheBudgetIsRefusedForGood(t *testing.T) {
	q := budgetGateway(t, 1, nil) // 1 EUR; the reservation is 3 or more
	resp := q.post(t, q.key, smallChat)
	if resp.StatusCode != 429 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e := readError(t, resp)
	if e.Code != "quota_exceeded" || !strings.Contains(e.Message, "larger than the limit") || resp.Header.Get("Retry-After") != "" {
		t.Errorf("%+v retry-after %q", e, resp.Header.Get("Retry-After"))
	}
}

func TestFailedCallsGiveTheirMoneyBack(t *testing.T) {
	// room for one reservation (about 3.5 EUR) and not two
	q := budgetGateway(t, 5, nil)
	for i := 0; i < 5; i++ {
		resp := q.post(t, q.key, `{"model":"broken","max_tokens":5,"messages":[{"role":"user","content":"hello there world"}]}`)
		if resp.StatusCode != 500 {
			t.Fatalf("broken model: status %d", resp.StatusCode)
		}
	}
	if resp := q.post(t, q.key, smallChat); resp.StatusCode != 200 {
		t.Errorf("status %d: failed calls kept their money", resp.StatusCode)
	}
}

func TestWhatHasNoPriceDoesNotUseTheBudget(t *testing.T) {
	q := budgetGateway(t, 1, func(*config.Snapshot) {}) // no prices at all
	for i := 0; i < 10; i++ {
		if resp := q.post(t, q.key, smallChat); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	if d := lastDecision(t, q.fixture); d.Quota != nil && d.Quota.ReservedMicroEUR != 0 {
		t.Errorf("reserved %d micro-EUR for an unpriced route", d.Quota.ReservedMicroEUR)
	}
}

func TestOnlyTheTeamsBudgetIsUsed(t *testing.T) {
	q := budgetGateway(t, 1, nil) // research: 1 EUR, too little for any request
	if resp := q.post(t, q.key, smallChat); resp.StatusCode != 429 {
		t.Fatalf("research: status %d", resp.StatusCode)
	}
	if resp := q.post(t, q.conf, smallChat); resp.StatusCode != 200 { // finance has no budget policy
		t.Errorf("finance: status %d", resp.StatusCode)
	}
}

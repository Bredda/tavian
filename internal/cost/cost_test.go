package cost

import (
	"math"
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }

func TestComputePricesInputCachedAndOutput(t *testing.T) {
	p := Price{Input: 2, Output: 6, CachedInput: f(0.5)}
	// 1000 input of which 400 cached, 500 output: 600*2 + 400*0.5 + 500*6
	r := Compute(Usage{Input: 1000, Cached: 400, Output: 500}, &p, nil, nil, "")
	if r.CostMicroEUR == nil || *r.CostMicroEUR != 4400 {
		t.Fatalf("cost = %v, want 4400", r.CostMicroEUR)
	}
	if r.EnergyWh != nil || r.CO2eGrams != nil {
		t.Error("energy or carbon without a profile")
	}
	if r.Basis == nil || *r.Basis.PriceInputPer1MEUR != 2 || *r.Basis.PriceCachedPer1MEUR != 0.5 || r.Basis.Estimate {
		t.Errorf("basis = %+v", r.Basis)
	}
}

func TestCachedTokensCostAsInputWithoutACachedPrice(t *testing.T) {
	p := Price{Input: 2, Output: 6}
	r := Compute(Usage{Input: 1000, Cached: 400}, &p, nil, nil, "")
	if *r.CostMicroEUR != 2000 {
		t.Fatalf("cost = %d", *r.CostMicroEUR)
	}
}

func TestCostIsRoundedOncePerRequest(t *testing.T) {
	p := Price{Input: 0.5, Output: 0.5}
	for _, c := range []struct {
		in, out, want int64
	}{{1, 0, 1}, {0, 1, 1}, {3, 0, 2}, {1, 1, 1}, {0, 0, 0}, {2, 1, 2}} {
		got := PriceMicroEUR(p, Usage{Input: c.in, Output: c.out})
		if got != c.want {
			t.Errorf("%d in, %d out = %d, want %d", c.in, c.out, got, c.want)
		}
	}
}

func TestOddUsageNeverGivesANegativeCost(t *testing.T) {
	p := Price{Input: 2, Output: 6, CachedInput: f(1)}
	for _, u := range []Usage{{Input: -5, Output: -5}, {Input: 10, Cached: 50}, {Input: 10, Cached: -3}} {
		if got := PriceMicroEUR(p, u); got < 0 {
			t.Errorf("%+v costs %d", u, got)
		}
	}
	// cached tokens above the input are capped at the input
	if got := PriceMicroEUR(p, Usage{Input: 10, Cached: 50}); got != 10 {
		t.Errorf("cached above input = %d, want 10 (10 cached tokens at 1)", got)
	}
}

func TestEnergyAndCarbon(t *testing.T) {
	e := Energy{WhPer1KInput: 0.3, WhPer1KOutput: 1.2, Method: MethodEstimated, Confidence: ConfidenceLow}
	r := Compute(Usage{Input: 2000, Output: 500}, nil, &e, f(50), "fr-par")
	// 2*0.3 + 0.5*1.2 = 1.2 Wh; 1.2 Wh = 0.0012 kWh * 50 g = 0.06 g
	if r.EnergyWh == nil || math.Abs(*r.EnergyWh-1.2) > 1e-9 {
		t.Fatalf("energy = %v", r.EnergyWh)
	}
	if r.CO2eGrams == nil || math.Abs(*r.CO2eGrams-0.06) > 1e-9 {
		t.Fatalf("carbon = %v", r.CO2eGrams)
	}
	if r.CostMicroEUR != nil {
		t.Error("cost without a price")
	}
	b := r.Basis
	if b == nil || !b.Estimate || b.EnergyMethod != "estimated" || b.EnergyConfidence != "low" || b.Region != "fr-par" || *b.CarbonGPerKWh != 50 {
		t.Errorf("basis = %+v", b)
	}
}

func TestNothingIsInventedWhenSomethingIsMissing(t *testing.T) {
	e := Energy{WhPer1KInput: 1, WhPer1KOutput: 1, Method: MethodMeasured, Confidence: ConfidenceHigh}
	if r := Compute(Usage{Input: 100}, nil, &e, nil, ""); r.EnergyWh == nil || r.CO2eGrams != nil {
		t.Errorf("energy without an intensity: %+v", r)
	}
	if r := Compute(Usage{Input: 100}, nil, nil, f(50), "x"); r.CostMicroEUR != nil || r.EnergyWh != nil || r.CO2eGrams != nil || r.Basis != nil {
		t.Errorf("an intensity alone produced %+v", r)
	}
	zero := Energy{Method: MethodEstimated, Confidence: ConfidenceLow}
	if r := Compute(Usage{Input: 100}, nil, &zero, f(50), ""); r.EnergyWh == nil || *r.EnergyWh != 0 {
		t.Error("a profile of zero is a profile")
	}
}

func TestEstimateAssumesNothingIsCached(t *testing.T) {
	p := Price{Input: 2, Output: 6, CachedInput: f(0.1)}
	if got := EstimateMicroEUR(p, 1000, 100); got != 2600 {
		t.Fatalf("estimate = %d, want 2600", got)
	}
}

func TestValidate(t *testing.T) {
	for name, p := range map[string]Price{
		"negative input": {Input: -1}, "nan": {Output: math.NaN()}, "inf": {Input: math.Inf(1)},
		"huge": {Output: 1e9}, "bad cached": {CachedInput: f(-2)},
		"just over the bound": {Input: maxPrice + 1}, "cached just over": {CachedInput: f(maxPrice + 1)},
	} {
		if p.Validate() == nil {
			t.Errorf("price %s accepted", name)
		}
	}
	if err := (Price{Input: 0, Output: 0}).Validate(); err != nil {
		t.Errorf("a free model: %v", err)
	}
	if err := (Price{Input: maxPrice, Output: maxPrice, CachedInput: f(maxPrice)}).Validate(); err != nil {
		t.Errorf("a price at the bound: %v", err)
	}
	ok := Energy{WhPer1KInput: 1, WhPer1KOutput: 2, Method: MethodBenchmark, Confidence: ConfidenceMedium}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Energy){
		"negative":  func(e *Energy) { e.WhPer1KInput = -1 },
		"nan":       func(e *Energy) { e.WhPer1KOutput = math.NaN() },
		"huge":      func(e *Energy) { e.WhPer1KOutput = 1e9 },
		"method":    func(e *Energy) { e.Method = "guess" },
		"no method": func(e *Energy) { e.Method = "" },
		"conf":      func(e *Energy) { e.Confidence = "certain" },
	} {
		e := ok
		mutate(&e)
		if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "energy.") {
			t.Errorf("energy %s: %v", name, err)
		}
	}
}

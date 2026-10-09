// Package cost turns the tokens of a request into money, energy and carbon
// (docs/QUOTAS_AND_METERING.md, ADR-0009).
//
// Prices, energy factors and carbon intensities are set in the configuration.
// Nothing is invented: without a price there is no cost, without an energy
// profile no energy, without an intensity no carbon. Energy and carbon are
// estimates, labelled as such wherever they appear.
package cost

import (
	"fmt"
	"math"
)

// Price is what a backend charges for one upstream model, in EUR per million
// tokens (so 0.50 is 0.50 micro-EUR per token).
type Price struct {
	Input  float64 `yaml:"input" json:"input_per_1m_eur"`
	Output float64 `yaml:"output" json:"output_per_1m_eur"`
	// CachedInput is the price of input tokens served from the backend's
	// cache; without it they cost as much as any input token.
	CachedInput *float64 `yaml:"cached_input" json:"cached_input_per_1m_eur,omitempty"`
}

// Energy methods, from the weakest claim to the strongest.
const (
	MethodEstimated = "estimated" // a generic figure
	MethodBenchmark = "benchmark" // published figures for that class of model
	MethodMeasured  = "measured"  // power measured on the machines that serve it
)

// Confidence levels.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Energy is the electricity a backend uses for one upstream model, per
// thousand tokens, and how the figure was obtained.
type Energy struct {
	WhPer1KInput  float64 `yaml:"wh_per_1k_input_tokens" json:"wh_per_1k_input_tokens"`
	WhPer1KOutput float64 `yaml:"wh_per_1k_output_tokens" json:"wh_per_1k_output_tokens"`
	Method        string  `yaml:"method" json:"method"`
	Confidence    string  `yaml:"confidence" json:"confidence"`
}

// maxPrice and maxWh bound what a configuration may say, to catch a misplaced
// decimal point rather than to model reality.
const (
	maxPrice     = 100000.0 // EUR per million tokens
	maxWh        = 100000.0 // Wh per thousand tokens
	MaxIntensity = 2000.0   // gCO2e per kWh
)

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Validate checks a price.
func (p Price) Validate() error {
	for name, v := range map[string]float64{"input": p.Input, "output": p.Output} {
		if !finite(v) || v < 0 || v > maxPrice {
			return fmt.Errorf("price.%s: must be between 0 and %g", name, maxPrice)
		}
	}
	if p.CachedInput != nil && (!finite(*p.CachedInput) || *p.CachedInput < 0 || *p.CachedInput > maxPrice) {
		return fmt.Errorf("price.cached_input: must be between 0 and %g", maxPrice)
	}
	return nil
}

// Validate checks an energy profile.
func (e Energy) Validate() error {
	for name, v := range map[string]float64{"wh_per_1k_input_tokens": e.WhPer1KInput, "wh_per_1k_output_tokens": e.WhPer1KOutput} {
		if !finite(v) || v < 0 || v > maxWh {
			return fmt.Errorf("energy.%s: must be between 0 and %g", name, maxWh)
		}
	}
	switch e.Method {
	case MethodEstimated, MethodBenchmark, MethodMeasured:
	default:
		return fmt.Errorf("energy.method: must be estimated, benchmark or measured (got %q)", e.Method)
	}
	switch e.Confidence {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
	default:
		return fmt.Errorf("energy.confidence: must be low, medium or high (got %q)", e.Confidence)
	}
	return nil
}

// Usage is what a request consumed, as the backend reported it. Cached is a
// part of Input, and reasoning tokens are part of Output, as in the OpenAI API.
type Usage struct{ Input, Output, Cached int64 }

// Basis is what a cost was computed from, kept with the usage event so that it
// can be read later without the configuration of the day. Energy and carbon
// are estimates.
type Basis struct {
	PriceInputPer1MEUR  *float64 `json:"price_input_per_1m_eur,omitempty"`
	PriceOutputPer1MEUR *float64 `json:"price_output_per_1m_eur,omitempty"`
	PriceCachedPer1MEUR *float64 `json:"price_cached_input_per_1m_eur,omitempty"`
	WhPer1KInput        *float64 `json:"wh_per_1k_input_tokens,omitempty"`
	WhPer1KOutput       *float64 `json:"wh_per_1k_output_tokens,omitempty"`
	EnergyMethod        string   `json:"energy_method,omitempty"`
	EnergyConfidence    string   `json:"energy_confidence,omitempty"`
	Region              string   `json:"region,omitempty"`
	CarbonGPerKWh       *float64 `json:"carbon_g_per_kwh,omitempty"`
	// Estimate is always true for energy and carbon: they are not measured
	// per request.
	Estimate bool `json:"estimate,omitempty"`
}

// Result is the cost of a request. A field is nil when what it needs is not
// configured.
type Result struct {
	CostMicroEUR *int64
	EnergyWh     *float64
	CO2eGrams    *float64
	Basis        *Basis
}

// Compute prices a request. price and energy are those of the route taken,
// intensity (gCO2e per kWh) that of its region; any of them may be nil.
func Compute(u Usage, price *Price, energy *Energy, intensity *float64, region string) Result {
	var r Result
	b := Basis{Region: region}
	used := false
	if price != nil {
		micro := PriceMicroEUR(*price, u)
		r.CostMicroEUR = &micro
		b.PriceInputPer1MEUR, b.PriceOutputPer1MEUR, b.PriceCachedPer1MEUR = &price.Input, &price.Output, price.CachedInput
		used = true
	}
	if energy != nil {
		wh := float64(u.Input)/1000*energy.WhPer1KInput + float64(u.Output)/1000*energy.WhPer1KOutput
		r.EnergyWh = &wh
		b.WhPer1KInput, b.WhPer1KOutput = &energy.WhPer1KInput, &energy.WhPer1KOutput
		b.EnergyMethod, b.EnergyConfidence, b.Estimate = energy.Method, energy.Confidence, true
		used = true
		if intensity != nil {
			g := wh / 1000 * *intensity
			r.CO2eGrams = &g
			b.CarbonGPerKWh = intensity
		}
	}
	if used {
		r.Basis = &b
	}
	return r
}

// PriceMicroEUR is the cost of u under p in micro-euros, rounded once for the
// request. Cached tokens that exceed the input are ignored.
func PriceMicroEUR(p Price, u Usage) int64 {
	cached := min(max(u.Cached, 0), max(u.Input, 0))
	cachedPrice := p.Input
	if p.CachedInput != nil {
		cachedPrice = *p.CachedInput
	}
	v := float64(max(u.Input, 0)-cached)*p.Input + float64(cached)*cachedPrice + float64(max(u.Output, 0))*p.Output
	return int64(math.Round(v))
}

// EstimateMicroEUR is what a request may cost at most, for reserving budget:
// every input token at the input price, up to maxOutput tokens of answer.
func EstimateMicroEUR(p Price, inputTokens, maxOutput int64) int64 {
	return PriceMicroEUR(p, Usage{Input: inputTokens, Output: maxOutput})
}

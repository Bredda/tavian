package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus instruments. Label values are drawn from small
// bounded sets (route, outcome, model and backend names from the config);
// users, keys and request ids are never labels.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	tokens   *prometheus.CounterVec
}

// NewMetrics creates a private registry (no global state) with the Go and
// process collectors.
func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_requests_total",
			Help: "Requests handled, by route and outcome.",
		}, []string{"route", "outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tavian_request_duration_seconds",
			Help:    "Request duration, by route.",
			Buckets: []float64{.05, .25, 1, 2.5, 10, 30, 60, 120, 300},
		}, []string{"route"}),
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_tokens_total",
			Help: "Tokens processed, by model, backend and direction (input|output).",
		}, []string{"model", "backend", "direction"}),
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requests, m.duration, m.tokens,
	)
	return m
}

// Handler serves the metrics in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

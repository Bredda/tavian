package server

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bredda/tavian/internal/config"
)

// Metrics holds the Prometheus instruments. Label values are drawn from small
// bounded sets (route, outcome, model and backend names from the config);
// users, keys and request ids are never labels.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	tokens   *prometheus.CounterVec

	eventsLost prometheus.Counter
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
		eventsLost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tavian_usage_events_lost_total",
			Help: "Usage events that could be neither stored nor spooled. Any increase is an audit gap.",
		}),
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requests, m.duration, m.tokens, m.eventsLost,
	)
	return m
}

// Handler serves the metrics in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// WatchStorage exposes the state of the usage-event pipeline: whether the
// database is believed reachable and how many bytes wait in the spool.
func (m *Metrics) WatchStorage(up func() bool, spoolBytes func() int64) {
	m.reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tavian_database_up",
			Help: "1 if PostgreSQL is believed reachable, 0 if events are being spooled.",
		}, func() float64 {
			if up() {
				return 1
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tavian_spool_bytes",
			Help: "Bytes of usage events waiting on disk for PostgreSQL.",
		}, func() float64 { return float64(spoolBytes()) }),
	)
}

// WatchOIDC exposes how old the identity provider's cached signing keys are
// (-1 until the first fetch succeeds). Past oidc.jwks_max_staleness every
// token is refused, so alert before that.
func (m *Metrics) WatchOIDC(keysAgeSeconds func() float64) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tavian_oidc_jwks_age_seconds",
		Help: "Age of the cached OIDC signing keys in seconds, -1 if none were fetched yet.",
	}, keysAgeSeconds))
}

// WatchInflight exposes the number of API requests being handled right now.
func (m *Metrics) WatchInflight(inflight func() float64) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tavian_inflight_requests",
		Help: "API requests being handled right now (limits.max_inflight caps this).",
	}, inflight))
}

// WatchAPIKeys exposes API key expiry from the current configuration (so a
// reload is reflected at the next scrape). Key ids are not labels: the logs
// name the keys, the metrics say whether to look.
func (m *Metrics) WatchAPIKeys(snap *config.Holder, now func() time.Time) {
	m.reg.MustRegister(&keyExpiryCollector{snap: snap, now: now})
}

var (
	descKeyNext = prometheus.NewDesc("tavian_api_keys_next_expiry_seconds",
		"Seconds until the nearest expiry among API keys that have not expired yet; absent if no key expires.", nil, nil)
	descKeyExpired = prometheus.NewDesc("tavian_api_keys_expired",
		"Configured API keys past their expires_at (refused with 401).", nil, nil)
)

type keyExpiryCollector struct {
	snap *config.Holder
	now  func() time.Time
}

func (c *keyExpiryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descKeyNext
	ch <- descKeyExpired
}

func (c *keyExpiryCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snap.Load()
	if s == nil {
		return
	}
	e := s.KeyExpiries(c.now(), 0)
	ch <- prometheus.MustNewConstMetric(descKeyExpired, prometheus.GaugeValue, float64(len(e.Expired)))
	if e.HasNext {
		ch <- prometheus.MustNewConstMetric(descKeyNext, prometheus.GaugeValue, e.Next.Seconds())
	}
}

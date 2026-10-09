package server

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bredda/tavian/internal/chain"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/policy"
)

// Metrics holds the Prometheus instruments. Label values are drawn from small
// bounded sets (route, outcome, model and backend names from the config);
// users, keys and request ids are never labels.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	tokens   *prometheus.CounterVec

	labels      *prometheus.CounterVec
	actions     *prometheus.CounterVec
	shadow      *prometheus.CounterVec
	inspections *prometheus.CounterVec
	findings    *prometheus.CounterVec
	inspectTime prometheus.Histogram

	quotaExceeded *prometheus.CounterVec
	quotaEstimate prometheus.Histogram

	consumerEvents  *prometheus.CounterVec
	consumerErrors  *prometheus.CounterVec
	consumerPending *prometheus.GaugeVec

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
		labels: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_requests_by_label_total",
			Help: "Chat requests by classification label (public|internal|confidential|restricted), refused ones included.",
		}, []string{"label"}),
		actions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_policy_actions_total",
			Help: "Requests on which a policy action applied, by action (block|restrict_destinations|redact|flag).",
		}, []string{"action"}),
		shadow: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_policy_shadow_total",
			Help: "Requests on which policies in shadow mode would have changed the outcome, by what they would have changed (model|block|label|destinations|redact|clearance|error). Nothing was enforced.",
		}, []string{"change"}),
		inspections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_inspections_total",
			Help: "Request inspections, by status (ok|skipped|failed).",
		}, []string{"status"}),
		findings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_inspection_findings_total",
			Help: "Findings, by type and subtype. Never carries content.",
		}, []string{"type", "subtype"}),
		inspectTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tavian_inspection_duration_seconds",
			Help:    "Time spent inspecting a request.",
			Buckets: []float64{.0001, .0005, .001, .0025, .005, .01, .025, .05, .1},
		}),
		quotaExceeded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_quota_exceeded_total",
			Help: "Requests that went over a quota, by dimension, scope kind and effect (refused|soft|shadow). Every refusal is counted, recorded or not.",
		}, []string{"dimension", "scope", "effect"}),
		quotaEstimate: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tavian_quota_estimate_ratio",
			Help:    "Tokens a request really used divided by the tokens reserved for it. Above 1 the estimate was too low.",
			Buckets: []float64{.01, .05, .1, .25, .5, .75, 1, 1.5, 2},
		}),
		consumerEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_outbox_consumer_events_total",
			Help: "Outbox events handled, by consumer.",
		}, []string{"consumer"}),
		consumerErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tavian_outbox_consumer_errors_total",
			Help: "Failed turns of an outbox consumer (retried). A steady increase means events are not being processed.",
		}, []string{"consumer"}),
		consumerPending: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tavian_outbox_consumer_pending",
			Help: "Outbox events waiting for a consumer (counted up to 10001).",
		}, []string{"consumer"}),
		eventsLost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tavian_usage_events_lost_total",
			Help: "Usage events that could be neither stored nor spooled. Any increase is an audit gap.",
		}),
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requests, m.duration, m.tokens, m.eventsLost,
		m.inspections, m.findings, m.inspectTime, m.labels, m.actions, m.shadow, m.quotaExceeded, m.quotaEstimate, m.consumerEvents, m.consumerErrors, m.consumerPending,
	)
	return m
}

// Handler serves the metrics in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// WatchStorage exposes the state of the usage-event pipeline: whether the
// database is believed reachable and how many bytes wait in the spool.
func (m *Metrics) WatchStorage(up func() bool, spoolBytes func() int64, rejected func() int64) {
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
			Help: "Bytes of events waiting on disk for PostgreSQL.",
		}, func() float64 { return float64(spoolBytes()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "tavian_spool_rejected_records_total",
			Help: "Spooled records that could not be read back and were set aside in events.rejected. Any increase needs a look.",
		}, func() float64 { return float64(rejected()) }),
	)
}

// ObserveConsumer records one turn of an outbox consumer.
func (m *Metrics) ObserveConsumer(c outbox.Cycle) {
	if c.Skipped {
		return
	}
	m.consumerEvents.WithLabelValues(c.Consumer).Add(float64(c.Handled))
	if c.Err != nil {
		m.consumerErrors.WithLabelValues(c.Consumer).Inc()
		return
	}
	m.consumerPending.WithLabelValues(c.Consumer).Set(float64(c.Pending))
}

// WatchAudit exposes the audit chain: its length, the entries no seal covers
// yet and the age of the last seal (-1 if there is none). With a signing key
// configured, an age that keeps growing means sealing is stuck.
func (m *Metrics) WatchAudit(stats func() chain.Stats, now func() time.Time) {
	m.reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tavian_audit_chain_entries",
			Help: "Decision records in the hash chain.",
		}, func() float64 { return float64(stats().Entries) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tavian_audit_unsealed_entries",
			Help: "Chain entries after the last seal, not yet covered by a signature.",
		}, func() float64 { return float64(stats().Unsealed) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "tavian_audit_seconds_since_last_seal",
			Help: "Seconds since the last seal was made, -1 if none (no signing key, or no seal yet).",
		}, func() float64 {
			t := stats().LastSeal
			if t.IsZero() {
				return -1
			}
			return now().Sub(t).Seconds()
		}),
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

// observeInspection records one inspection.
func (m *Metrics) observeInspection(r inspect.Result) {
	m.inspections.WithLabelValues(r.Status).Inc()
	if r.Status == inspect.StatusSkipped {
		return
	}
	m.inspectTime.Observe(r.Duration.Seconds())
	for _, f := range r.Findings {
		m.findings.WithLabelValues(string(f.Type), f.Subtype).Inc()
	}
}

// observeLabel counts a classified request.
func (m *Metrics) observeLabel(l config.Classification) {
	m.labels.WithLabelValues(string(l)).Inc()
}

// observeActions counts the policy actions that applied to a request.
func (m *Metrics) observeActions(d policy.Decision) {
	if d.Block != nil {
		m.actions.WithLabelValues(policy.ActionBlock).Inc()
		return
	}
	if d.Restricted != nil {
		m.actions.WithLabelValues(policy.ActionRestrict).Inc()
	}
	if len(d.Redact) > 0 {
		m.actions.WithLabelValues(policy.ActionRedact).Inc()
	}
	if len(d.Flagged) > 0 {
		m.actions.WithLabelValues(policy.ActionFlag).Inc()
	}
}

// observeShadow counts what policies in shadow mode would have changed.
func (m *Metrics) observeShadow(sh *policy.Shadow) {
	if sh == nil {
		return
	}
	for change, hit := range map[string]bool{
		"block": sh.WouldBlock != nil, "label": sh.Label != "", "destinations": sh.ClassesChanged,
		"redact": len(sh.WouldRedact) > 0, "clearance": sh.ExceedsClearance, "error": sh.Error != "",
	} {
		if hit {
			m.shadow.WithLabelValues(change).Inc()
		}
	}
}

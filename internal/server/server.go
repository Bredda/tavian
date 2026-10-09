// Package server wires the HTTP surface: the OpenAI-compatible data plane and
// the admin listener (health, readiness, metrics).
//
// The chat handler is the M1 version of the request lifecycle described in
// docs/ARCHITECTURE.md §4. Steps that do not exist yet are marked TODO(Mn) at
// the place they will be inserted, so the shape of the pipeline is already
// the final one.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/bredda/tavian/internal/admin"
	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/cost"
	"github.com/bredda/tavian/internal/docs"
	"github.com/bredda/tavian/internal/ids"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/meter"
	"github.com/bredda/tavian/internal/pipeline"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/provider/openai"
	"github.com/bredda/tavian/internal/quota"
	"github.com/bredda/tavian/internal/router"
	"github.com/bredda/tavian/internal/version"
)

// Deps are the collaborators of the data plane.
type Deps struct {
	Snap     *config.Holder
	Auth     auth.Authenticator
	Provider *openai.Client
	Sink     meter.Sink
	Log      *slog.Logger
	Metrics  *Metrics
	// Route picks the backend of a request; nil means router.Resolve. Tests
	// replace it to check that phase B catches a faulty router.
	Route RouteFunc
	// Quota holds the quota counters and Coalescer limits how often quota
	// refusals are recorded; nil means new ones. Tests pass their own, with a
	// clock they control.
	Quota     *quota.Store
	Coalescer *quota.Coalescer
}

// RouteFunc is the signature of router.Resolve.
type RouteFunc = pipeline.RouteFunc

type ctxKey struct{}

// RequestID returns the id attached to ctx by the request-id middleware.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// NewDataHandler returns the OpenAI-compatible API.
func NewDataHandler(d Deps) http.Handler {
	if d.Quota == nil {
		d.Quota = quota.NewStore(nil)
	}
	if d.Coalescer == nil {
		d.Coalescer = quota.NewCoalescer(nil)
	}
	s := &server{Deps: d}
	d.Metrics.WatchInflight(func() float64 { return float64(s.inflight.Load()) })
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.instrument("chat_completions", s.chat))
	mux.HandleFunc("GET /v1/models", s.instrument("models", s.models))
	docs.Register(mux, version.String(), func() bool {
		snap := d.Snap.Load()
		return snap != nil && snap.DocsEnabled
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "invalid_request_error", "not_found", "unknown endpoint")
	})
	return s.requestID(s.recoverer(s.accessLog(mux)))
}

// NewAdminHandler returns the health, readiness and metrics endpoints and,
// when adm is not nil, the administration API with its reference (it answers
// 404 until an admin token is configured).
//
// audit may be nil. When set, readiness also requires that the audit trail can
// still record events: a gateway that must refuse requests is not ready.
func NewAdminHandler(snap *config.Holder, m *Metrics, audit meter.Admitter, adm *admin.Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if snap.Load() == nil {
			http.Error(w, "no configuration loaded", http.StatusServiceUnavailable)
			return
		}
		if audit != nil {
			if err := audit.Admit(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.Handle("GET /metrics", m.Handler())
	if adm != nil {
		d := *adm
		d.Snap = snap
		if d.Observe == nil {
			d.Observe = m.ObserveAdmin
		}
		admin.Register(mux, d)
		docs.RegisterAdmin(mux, version.String(), func() bool { return admin.Enabled(snap) })
	}
	return mux
}

type server struct {
	Deps
	inflight atomic.Int64
}

// models lists the models the caller may use.
func (s *server) models(w http.ResponseWriter, r *http.Request) string {
	snap := s.Snap.Load()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error", "not_ready", "gateway not ready")
		return "not_ready"
	}
	id, err := s.Auth.Authenticate(r)
	if err != nil {
		s.Log.InfoContext(r.Context(), "authentication failed", "reason", auth.Reason(err))
		unauthorized(w)
		return "unauthenticated"
	}
	data := []map[string]any{}
	for _, name := range snap.ModelNames {
		if id.CanUseModel(name) {
			data = append(data, map[string]any{
				"id": name, "object": "model", "created": snap.LoadedAt.Unix(), "owned_by": "tavian",
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
	return "ok"
}

// decisionHeader carries the id of the decision record of a request. It is the
// same id as the "decision_id" of error bodies and of the record in the outbox.
const decisionHeader = "X-Tavian-Decision-Id"

// call is what the chat handler knows about the request it is deciding.
type call struct {
	snap       *config.Snapshot
	id         *auth.Identity
	decisionID string
	at         time.Time
	model      string
	inspection *inspect.Result
	decision   *policy.Decision
	matched    []string // policy rules and policies that acted
	redactions map[string]int
	shadow     *audit.Shadow
	candidates []router.Candidate
	quota      *audit.Quota
}

// record starts the decision record of c.
func (c *call) record(ctx context.Context, outcome string, reason audit.Reason, status int) audit.DecisionRecord {
	rec := audit.DecisionRecord{
		DecisionID:  c.decisionID,
		RequestID:   RequestID(ctx),
		Time:        c.at.UTC(),
		Revision:    c.snap.Revision,
		AuthMethod:  c.id.Method,
		KeyID:       c.id.KeyID,
		UserID:      c.id.Subject,
		Team:        c.id.Team,
		Application: c.id.Application,
		Model:       c.model,
		Outcome:     outcome,
		ReasonCode:  reason.Code,
		Status:      status,
	}
	if c.inspection != nil {
		rec.WithInspection(*c.inspection)
	}
	for _, cand := range c.candidates {
		rec.Candidates = append(rec.Candidates, audit.Candidate{Backend: cand.Backend, Excluded: cand.Excluded})
	}
	rec.RulesMatched = c.matched
	rec.Redactions = c.redactions
	rec.Shadow = c.shadow
	rec.Quota = c.quota
	if c.decision != nil {
		rec.Label = string(c.decision.Label)
		rec.LabelSources = &audit.LabelSources{
			Declared: string(c.decision.Sources.Declared),
			Default:  string(c.decision.Sources.Default),
			Inferred: string(c.decision.Sources.Inferred),
		}
		rec.Constraints = c.decision.Constraints.ClassNames()
	}
	return rec
}

// refuse records the decision to refuse the request, then answers. The record
// is stored before the answer is sent, so the decision_id the caller receives
// always exists; if it cannot be stored the request fails closed (ADR-0005).
// It returns the outcome label for metrics.
func (s *server) refuse(ctx context.Context, w http.ResponseWriter, c *call, reason audit.Reason, msg, label string) string {
	if err := s.emit(ctx, c.record(ctx, audit.OutcomeRefused, reason, reason.Status)); err != nil {
		s.Log.ErrorContext(ctx, "refusal could not be recorded", "reason", reason.Code, "error", err)
		w.Header().Del(decisionHeader)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "server_error", "audit_unavailable", "the gateway cannot record this request right now")
		return "audit_unavailable"
	}
	writeErrorWithDecision(w, reason.Status, reason.Type, reason.Client, msg, c.decisionID)
	return label
}

// chat handles POST /v1/chat/completions.
func (s *server) chat(w http.ResponseWriter, r *http.Request) string {
	ctx := r.Context()
	snap := s.Snap.Load()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error", "not_ready", "gateway not ready")
		return "not_ready"
	}

	// authenticate. Until the caller is known nothing is recorded in the audit
	// trail: anyone could otherwise fill it.
	id, err := s.Auth.Authenticate(r)
	if err != nil {
		s.Log.InfoContext(r.Context(), "authentication failed", "reason", auth.Reason(err))
		unauthorized(w)
		return "unauthenticated"
	}

	// Fail closed (ADR-0005): do not serve a request whose records could not
	// be stored.
	if a, ok := s.Sink.(meter.Admitter); ok {
		if err := a.Admit(); err != nil {
			s.Log.ErrorContext(ctx, "refusing request", "error", err)
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "server_error", "audit_unavailable", "the gateway cannot record this request right now")
			return "audit_unavailable"
		}
	}

	c := &call{snap: snap, id: id, decisionID: ids.New(), at: time.Now()}
	w.Header().Set(decisionHeader, c.decisionID)

	// admission: the cheap quotas (rpm, concurrency), before any work is
	// spent on the request. A request refused later still counts against rpm.
	limits := snap.Policy.Limits(policyIdentity(id))
	slot, admitted := s.Quota.Admit(limits)
	defer slot.Release()
	s.noteQuota(c, admitted)
	if admitted.Refused {
		return s.refuseQuota(ctx, w, c, admitted)
	}

	// receive (bounded)
	r.Body = http.MaxBytesReader(w, r.Body, snap.Limits.MaxRequestBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return s.refuse(ctx, w, c, audit.RequestTooLarge, "request body too large", "request_too_large")
		}
		return s.refuse(ctx, w, c, audit.InvalidRequest, "could not read request body", "invalid_request")
	}

	// normalize
	peeked, err := openai.Peek(raw)
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, err.Error(), "invalid_request")
	}
	model := peeked.Model
	c.model = model

	// authorize: the credentials must grant the model, and so must the policies
	// (before inspection, so that a refused model costs no inspection time)
	caller := pipeline.Caller{Identity: policyIdentity(id), Grants: id.AllowedModels, Clearance: id.MaxClassification}
	refusal, shadowModel := pipeline.AuthorizeModel(snap, caller, model)
	if refusal != nil {
		c.matched = append(c.matched, refusal.Matched...)
		return s.refuse(ctx, w, c, refusal.Reason, refusal.Message, refusal.Outcome)
	}
	if shadowModel != nil {
		c.shadow = &audit.Shadow{Policies: []string{shadowModel.Policy}, WouldDenyModel: shadowModel.Policy}
		s.Metrics.shadow.WithLabelValues("model").Inc()
	}

	// inspect (fail closed: a request that cannot be inspected is not served)
	creq, err := openai.ExtractChat(raw)
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, err.Error(), "invalid_request")
	}
	inspection, ierr := snap.Inspector.Inspect(ctx, creq)
	c.inspection = &inspection
	s.Metrics.observeInspection(inspection)
	if ierr != nil {
		reason := audit.FromInspection(inspect.CodeOf(ierr))
		msg := "the request contains content that cannot be inspected"
		switch reason {
		case audit.InspectionFailed:
			msg = "the request could not be inspected"
			s.Log.ErrorContext(ctx, "inspection failed", "error", ierr)
		case audit.RequestTooComplex:
			msg = "the request is too complex to be inspected"
		}
		return s.refuse(ctx, w, c, reason, msg, "inspection_blocked")
	}

	// policies, clearance, routing and phase B: the same code `tavian policy
	// test` runs
	declared, err := policy.ParseDeclared(r.Header.Values(policy.DeclaredHeader))
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, "invalid "+policy.DeclaredHeader+" header: expected one of public, internal, confidential, restricted", "invalid_request")
	}
	verdict := pipeline.Evaluate(snap, s.Route, caller, policy.Input{
		Identity: caller.Identity,
		Request:  policy.Request{Model: model, Stream: peeked.Stream, MaxTokens: peeked.MaxTokens, HasTools: peeked.HasTools},
		Declared: declared,
		Kinds:    inspection.Kinds,
	})
	c.candidates = verdict.Candidates
	if verdict.Decided {
		decision := verdict.Decision
		c.decision = &decision
		c.matched = append(c.matched, decision.Matched...)
		c.shadow = mergeShadow(c.shadow, decision.Shadow)
		s.Metrics.observeLabel(decision.Label)
		s.Metrics.observeActions(decision)
		s.Metrics.observeShadow(decision.Shadow)
	}
	if verdict.Err != nil {
		s.Log.ErrorContext(ctx, "the decision could not be completed", "outcome", verdict.Refusal.Outcome, "error", verdict.Err)
	}
	if verdict.Refusal != nil {
		return s.refuse(ctx, w, c, verdict.Refusal.Reason, verdict.Refusal.Message, verdict.Refusal.Outcome)
	}
	decision, route := verdict.Decision, verdict.Route

	// redact: replace what the policy says must not be sent, then check that
	// the result no longer holds it. The label stays that of the original
	// request, so redaction never opens a more external route.
	body := raw
	if len(decision.Redact) > 0 {
		redacted, reason, msg := s.redact(ctx, snap, raw, creq, inspection, decision, c)
		if msg != "" {
			return s.refuse(ctx, w, c, reason, msg, "redaction_failed")
		}
		body = redacted
	}
	upstreamBody, err := openai.RewriteChat(body, route.UpstreamModel)
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, err.Error(), "invalid_request")
	}

	// reserve the tokens the request may use against tpm and tokens_per_day;
	// settled below with what it really used
	maxOut := peeked.MaxTokens
	if maxOut <= 0 {
		maxOut = snap.Quota.DefaultOutputTokens
	}
	amount := quota.Amount{Tokens: quota.Estimate(len(upstreamBody), maxOut)}
	if route.Price != nil { // money, at the price of the backend that was chosen
		amount.MicroEUR = cost.EstimateMicroEUR(*route.Price, quota.Estimate(len(upstreamBody), 0), min(maxOut, 1<<40))
	}
	reservation, reserved := s.Quota.Reserve(limits, amount)
	s.noteQuota(c, reserved)
	if reserved.Refused {
		return s.refuseQuota(ctx, w, c, reserved)
	}
	if reservation != nil {
		if c.quota == nil {
			c.quota = &audit.Quota{}
		}
		c.quota.ReservedTokens = reservation.Tokens()
		c.quota.ReservedMicroEUR = reservation.MicroEUR()
	}

	// call provider and relay the response
	start := time.Now()
	res, err := s.Provider.ChatCompletions(ctx, w, route.Backend, upstreamBody, r.Header.Get("Accept"), model)

	outcome, reason, status := "ok", audit.Served, res.Status
	switch {
	case err != nil && !res.Started:
		s.Log.WarnContext(ctx, "backend call failed", "backend", route.Backend, "error", err)
		writeErrorWithDecision(w, http.StatusBadGateway, "server_error", "upstream_unavailable", "the model backend could not be reached", c.decisionID)
		outcome, reason, status = "upstream_error", audit.UpstreamUnavailable, http.StatusBadGateway
		res.Status = http.StatusBadGateway
	case err != nil && ctx.Err() != nil:
		outcome, reason = "client_gone", audit.ClientDisconnected
	case err != nil:
		s.Log.WarnContext(ctx, "relay interrupted", "backend", route.Backend, "error", err)
		outcome, reason = "stream_error", audit.StreamInterrupted
	case res.Status/100 != 2:
		outcome, reason = "upstream_error", audit.UpstreamError
	}

	// settle: what the answer really used replaces the reservation. When the
	// backend reported nothing, a failure used nothing and a success keeps its
	// estimate.
	var priced cost.Result // what the request cost, when the backend said what it used
	switch {
	case res.Usage.Known:
		priced = cost.Compute(cost.Usage{Input: res.Usage.Input, Output: res.Usage.Output, Cached: res.Usage.Cached},
			route.Price, route.Energy, route.Backend.CarbonGPerKWh, route.Backend.Region)
		used := quota.Amount{Tokens: res.Usage.Input + res.Usage.Output}
		if priced.CostMicroEUR != nil {
			used.MicroEUR = *priced.CostMicroEUR
		}
		reservation.Settle(used)
		if t := reservation.Tokens(); t > 0 {
			s.Metrics.quotaEstimate.Observe(float64(used.Tokens) / float64(t))
		}
	case res.Status/100 != 2:
		reservation.Settle(quota.Amount{})
	default:
		reservation.Settle(quota.Amount{Tokens: reservation.Tokens(), MicroEUR: reservation.MicroEUR()})
	}
	rec := c.record(ctx, audit.OutcomeServed, reason, status)
	if outcome != "ok" {
		rec.Outcome = audit.OutcomeFailed
	}
	rec.UpstreamModel, rec.Backend = route.UpstreamModel, route.Backend.ID
	rec.Cost = costOf(priced)
	s.emitOwed(ctx, rec)

	ev := s.event(ctx, c, start, outcome, res.Status)
	ev.UpstreamModel = route.UpstreamModel
	ev.Backend = route.Backend.ID
	ev.InputTokens = res.Usage.Input
	ev.OutputTokens = res.Usage.Output
	ev.CachedTokens = res.Usage.Cached
	ev.ReasoningTokens = res.Usage.Reasoning
	ev.UsageKnown = res.Usage.Known
	ev.CostMicroEUR, ev.EnergyWh, ev.CO2eGrams, ev.Basis = priced.CostMicroEUR, priced.EnergyWh, priced.CO2eGrams, priced.Basis
	ev.Streamed = res.Streamed
	ev.LatencyMS = time.Since(start).Milliseconds()
	ev.TTFBMS = res.TTFB.Milliseconds()
	s.emitOwed(ctx, ev)

	if res.Usage.Known {
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "input").Add(float64(res.Usage.Input))
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "output").Add(float64(res.Usage.Output))
		s.Metrics.observeCost(model, route.Backend.ID, priced)
	}
	return outcome
}

// costOf is the cost section of a decision record, nil when nothing was priced.
func costOf(r cost.Result) *audit.Cost {
	if r.CostMicroEUR == nil && r.EnergyWh == nil && r.CO2eGrams == nil {
		return nil
	}
	return &audit.Cost{MicroEUR: r.CostMicroEUR, EnergyWh: r.EnergyWh, CO2eGrams: r.CO2eGrams, Estimate: r.EnergyWh != nil}
}

// event starts the usage event of a request.
func (s *server) event(ctx context.Context, c *call, at time.Time, outcome string, status int) meter.UsageEvent {
	ev := meter.UsageEvent{
		EventID:     ids.New(),
		RequestID:   RequestID(ctx),
		DecisionID:  c.decisionID,
		Time:        at.UTC(),
		Revision:    c.snap.Revision,
		AuthMethod:  c.id.Method,
		KeyID:       c.id.KeyID,
		UserID:      c.id.Subject,
		Team:        c.id.Team,
		Application: c.id.Application,
		Model:       c.model,
		Status:      status,
		Outcome:     outcome,
	}
	if c.inspection != nil {
		sum := c.inspection.Summary()
		ev.Inspection = &sum
	}
	if c.decision != nil {
		ev.Label = string(c.decision.Label)
	}
	return ev
}

// emit stores e, detached from the request context: the client may be gone,
// the event is still owed.
func (s *server) emit(ctx context.Context, e meter.Event) error {
	return s.Sink.Emit(context.WithoutCancel(ctx), e)
}

// emitOwed stores an event of a request that was already served, so all that
// is left on failure is to say loudly that an event is lost. Admit makes that
// rare.
func (s *server) emitOwed(ctx context.Context, e meter.Event) {
	if err := s.emit(ctx, e); err != nil {
		s.Metrics.eventsLost.Inc()
		s.Log.ErrorContext(ctx, "event lost", "kind", e.Kind(), "id", e.ID(), "request_id", RequestID(ctx), "error", err)
	}
}

// --- middleware -------------------------------------------------------------

type handlerFunc func(http.ResponseWriter, *http.Request) string

// instrument records request count and duration for a route; the handler
// returns the outcome label.
func (s *server) instrument(route string, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		outcome := s.admit(w, h, r)
		if outcome == "" {
			outcome = "ok"
		}
		s.Metrics.requests.WithLabelValues(route, outcome).Inc()
		s.Metrics.duration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	}
}

// admit enforces limits.max_inflight before any other work: a gateway that
// takes on more requests than it can hold (each may buffer a request body and
// stream for minutes) serves nobody well. The limit is read from the current
// snapshot, so a reload changes it.
func (s *server) admit(w http.ResponseWriter, h handlerFunc, r *http.Request) string {
	n := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	if snap := s.Snap.Load(); snap != nil && n > int64(snap.Limits.MaxInflight) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "server_error", "server_busy", "the gateway is handling too many requests, retry shortly")
		return "overloaded"
	}
	return h(w, r)
}

func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !ids.Valid(id) {
			id = ids.New()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity per net/http docs
					panic(v)
				}
				s.Log.ErrorContext(r.Context(), "panic in handler", "panic", v)
				writeError(w, http.StatusInternalServerError, "server_error", "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// accessLog logs one line per request. It never logs bodies, headers or the
// query string.
func (s *server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.Log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("request_id", RequestID(r.Context())),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("bytes", rec.bytes),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

// --- responses --------------------------------------------------------------

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="tavian"`)
	writeError(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key", "missing or invalid credentials (API key or access token)")
}

// writeError sends an OpenAI-shaped error body. Messages never echo request
// content.
func writeError(w http.ResponseWriter, status int, typ, code, msg string) {
	writeErrorWithDecision(w, status, typ, code, msg, "")
}

// writeErrorWithDecision adds the decision_id of the record explaining the
// answer, when there is one.
func writeErrorWithDecision(w http.ResponseWriter, status int, typ, code, msg, decisionID string) {
	body := map[string]any{"message": msg, "type": typ, "code": code, "param": nil}
	if decisionID != "" {
		body["decision_id"] = decisionID
	}
	writeJSON(w, status, map[string]any{"error": body})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// policyIdentity is the caller as policies see it.
func policyIdentity(id *auth.Identity) policy.Identity {
	return policy.Identity{
		User: id.Subject, Groups: id.Groups, Team: id.Team, Application: id.Application, AuthMethod: id.Method,
	}
}

// redact applies the redact rules of d to the request. It returns the new body,
// or a reason and a message when the request cannot be served: too many
// findings to be sure all were replaced, or a redacted value still present in
// the result.
func (s *server) redact(ctx context.Context, snap *config.Snapshot, raw []byte, req inspect.Request, res inspect.Result, d policy.Decision, c *call) ([]byte, audit.Reason, string) {
	if res.Truncated {
		return nil, audit.RedactionIncomplete, "the request holds too many sensitive values to redact them all"
	}
	pick := func(f inspect.Finding) bool {
		return slices.Contains(d.Redact, policy.RedactKind{Type: f.Type, Subtype: f.Subtype})
	}
	r := inspect.Redact(req, res.Findings, pick)
	out, err := openai.RedactChat(raw, r.Replacements)
	if err != nil {
		s.Log.ErrorContext(ctx, "redaction failed", "error", err)
		return nil, audit.RedactionFailed, "the request could not be redacted"
	}
	// What was redacted must be gone: inspect the result and look for the same
	// values. This also catches a value that only became detectable once its
	// neighbour was replaced.
	again, err := openai.ExtractChat(out)
	var res2 inspect.Result
	if err == nil {
		res2, err = snap.Inspector.Inspect(ctx, again)
	}
	if err != nil || res2.Truncated {
		s.Log.ErrorContext(ctx, "redacted request could not be verified")
		return nil, audit.RedactionFailed, "the request could not be redacted"
	}
	gone := map[string]bool{}
	for _, f := range res.Findings {
		if pick(f) {
			gone[f.Fingerprint] = true
		}
	}
	for _, f := range res2.Findings {
		if gone[f.Fingerprint] {
			s.Log.ErrorContext(ctx, "a redacted value is still present after redaction", "kind", string(f.Type)+"."+f.Subtype)
			return nil, audit.RedactionFailed, "the request could not be redacted"
		}
	}
	c.redactions = r.Counts
	return out, audit.Reason{}, ""
}

// mergeShadow folds the shadow outcome of the decision into what the model
// authorization already noted, into the form the record keeps.
func mergeShadow(have *audit.Shadow, sh *policy.Shadow) *audit.Shadow {
	if sh == nil {
		return have
	}
	if have == nil {
		have = &audit.Shadow{}
	}
	for _, p := range sh.Policies {
		if !slices.Contains(have.Policies, p) {
			have.Policies = append(have.Policies, p)
		}
	}
	have.RulesMatched = sh.Matched
	if sh.WouldBlock != nil {
		have.WouldRefuse = sh.WouldBlock.Reason
	}
	have.Label = string(sh.Label)
	have.ExceedsClearance = sh.ExceedsClearance
	if sh.ClassesChanged {
		names := make([]string, len(sh.Classes))
		for i, c := range sh.Classes {
			names[i] = string(c)
		}
		have.Constraints = &names
	}
	for _, k := range sh.WouldRedact {
		have.WouldRedact = append(have.WouldRedact, string(k.Type)+"."+k.Subtype)
	}
	have.Error = sh.Error
	return have
}

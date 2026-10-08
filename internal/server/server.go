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
	"sync/atomic"
	"time"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/docs"
	"github.com/bredda/tavian/internal/ids"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/meter"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/provider/openai"
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
}

type ctxKey struct{}

// RequestID returns the id attached to ctx by the request-id middleware.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// NewDataHandler returns the OpenAI-compatible API.
func NewDataHandler(d Deps) http.Handler {
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

// NewAdminHandler returns the health, readiness and metrics endpoints.
//
// audit may be nil. When set, readiness also requires that the audit trail can
// still record events: a gateway that must refuse requests is not ready.
func NewAdminHandler(snap *config.Holder, m *Metrics, audit meter.Admitter) http.Handler {
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
	class      *policy.Classification
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
	if c.class != nil {
		rec.Label = string(c.class.Label)
		rec.LabelSources = &audit.LabelSources{
			Declared: string(c.class.Sources.Declared),
			Default:  string(c.class.Sources.Default),
			Inferred: string(c.class.Sources.Inferred),
		}
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
	model, _, err := openai.PeekChat(raw)
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, err.Error(), "invalid_request")
	}
	c.model = model

	// authorize
	if !id.CanUseModel(model) {
		return s.refuse(ctx, w, c, audit.ModelNotAllowed, "you may not use the requested model", "denied_model")
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

	// classify: the label is the most sensitive of what the caller declared,
	// the default and what inspection found; it must fit the caller's clearance.
	declared, err := policy.ParseDeclared(r.Header.Values(policy.DeclaredHeader))
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, "invalid "+policy.DeclaredHeader+" header: expected one of public, internal, confidential, restricted", "invalid_request")
	}
	class := policy.Classify(declared, inspection.Kinds)
	c.class = &class
	s.Metrics.observeLabel(class.Label)
	if class.Exceeds(id.MaxClassification) {
		return s.refuse(ctx, w, c, audit.ClearanceExceeded,
			"this request is classified "+string(class.Label)+", above the "+string(id.MaxClassification)+" your credentials are cleared to send", "clearance_exceeded")
	}

	// TODO(M2): policy phase A -> constraints (allowed destinations, redactions).

	// route
	route, err := router.Resolve(snap, model)
	if err != nil {
		return s.refuse(ctx, w, c, audit.ModelNotFound, "the requested model does not exist", "model_not_found")
	}
	upstreamBody, err := openai.RewriteChat(raw, route.UpstreamModel)
	if err != nil {
		return s.refuse(ctx, w, c, audit.InvalidRequest, err.Error(), "invalid_request")
	}

	// TODO(M2): policy phase B (assert the chosen backend satisfies constraints).
	// TODO(M2): quota reserve (tpm / budget) using the backend's price.

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

	// TODO(M2): quota settle with actual usage.
	rec := c.record(ctx, audit.OutcomeServed, reason, status)
	if outcome != "ok" {
		rec.Outcome = audit.OutcomeFailed
	}
	rec.UpstreamModel, rec.Backend = route.UpstreamModel, route.Backend.ID
	s.emitOwed(ctx, rec)

	ev := s.event(ctx, c, start, outcome, res.Status)
	ev.UpstreamModel = route.UpstreamModel
	ev.Backend = route.Backend.ID
	ev.InputTokens = res.Usage.Input
	ev.OutputTokens = res.Usage.Output
	ev.CachedTokens = res.Usage.Cached
	ev.ReasoningTokens = res.Usage.Reasoning
	ev.UsageKnown = res.Usage.Known
	ev.Streamed = res.Streamed
	ev.LatencyMS = time.Since(start).Milliseconds()
	ev.TTFBMS = res.TTFB.Milliseconds()
	s.emitOwed(ctx, ev)

	if res.Usage.Known {
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "input").Add(float64(res.Usage.Input))
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "output").Add(float64(res.Usage.Output))
	}
	return outcome
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
	if c.class != nil {
		ev.Label = string(c.class.Label)
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

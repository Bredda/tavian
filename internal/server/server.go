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

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/docs"
	"github.com/bredda/tavian/internal/ids"
	"github.com/bredda/tavian/internal/meter"
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

// chat handles POST /v1/chat/completions.
func (s *server) chat(w http.ResponseWriter, r *http.Request) string {
	ctx := r.Context()
	snap := s.Snap.Load()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error", "not_ready", "gateway not ready")
		return "not_ready"
	}

	// authenticate
	id, err := s.Auth.Authenticate(r)
	if err != nil {
		s.Log.InfoContext(r.Context(), "authentication failed", "reason", auth.Reason(err))
		unauthorized(w)
		return "unauthenticated"
	}

	// Fail closed (ADR-0005): do not serve a request whose usage event could
	// not be recorded.
	if a, ok := s.Sink.(meter.Admitter); ok {
		if err := a.Admit(); err != nil {
			s.Log.ErrorContext(ctx, "refusing request", "error", err)
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "server_error", "audit_unavailable", "the gateway cannot record this request right now")
			return "audit_unavailable"
		}
	}

	// receive (bounded)
	r.Body = http.MaxBytesReader(w, r.Body, snap.Limits.MaxRequestBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", "request body too large")
			return "request_too_large"
		}
		writeError(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", "could not read request body")
		return "invalid_request"
	}

	// normalize
	model, _, err := openai.PeekChat(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", err.Error())
		return "invalid_request"
	}

	// authorize
	if !id.CanUseModel(model) {
		writeError(w, http.StatusForbidden, "invalid_request_error", "model_not_allowed", "you may not use the requested model")
		return "denied_model"
	}

	// TODO(M2): inspect request content -> findings + classification label.
	// TODO(M2): policy phase A -> constraints (allowed destinations, redactions).

	// route
	route, err := router.Resolve(snap, model)
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid_request_error", "model_not_found", "the requested model does not exist")
		return "model_not_found"
	}
	upstreamBody, err := openai.RewriteChat(raw, route.UpstreamModel)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", err.Error())
		return "invalid_request"
	}

	// TODO(M2): policy phase B (assert the chosen backend satisfies constraints).
	// TODO(M2): quota reserve (tpm / budget) using the backend's price.

	// call provider and relay the response
	start := time.Now()
	res, err := s.Provider.ChatCompletions(ctx, w, route.Backend, upstreamBody, r.Header.Get("Accept"), model)

	outcome := "ok"
	switch {
	case err != nil && !res.Started:
		s.Log.WarnContext(ctx, "backend call failed", "backend", route.Backend, "error", err)
		writeError(w, http.StatusBadGateway, "server_error", "upstream_unavailable", "the model backend could not be reached")
		outcome = "upstream_error"
		res.Status = http.StatusBadGateway
	case err != nil && ctx.Err() != nil:
		outcome = "client_gone"
	case err != nil:
		s.Log.WarnContext(ctx, "relay interrupted", "backend", route.Backend, "error", err)
		outcome = "stream_error"
	case res.Status/100 != 2:
		outcome = "upstream_error"
	}

	// TODO(M2): quota settle with actual usage.
	ev := meter.UsageEvent{
		EventID:         ids.New(),
		RequestID:       RequestID(ctx),
		Time:            start.UTC(),
		Revision:        snap.Revision,
		AuthMethod:      id.Method,
		KeyID:           id.KeyID,
		UserID:          id.Subject,
		Team:            id.Team,
		Application:     id.Application,
		Model:           model,
		UpstreamModel:   route.UpstreamModel,
		Backend:         route.Backend.ID,
		InputTokens:     res.Usage.Input,
		OutputTokens:    res.Usage.Output,
		CachedTokens:    res.Usage.Cached,
		ReasoningTokens: res.Usage.Reasoning,
		UsageKnown:      res.Usage.Known,
		Streamed:        res.Streamed,
		Status:          res.Status,
		Outcome:         outcome,
		LatencyMS:       time.Since(start).Milliseconds(),
		TTFBMS:          res.TTFB.Milliseconds(),
	}
	// Detached from the request context: the client may be gone, the event is
	// still owed.
	if err := s.Sink.Emit(context.WithoutCancel(ctx), ev); err != nil {
		// Admit makes this rare; when it still happens the request is already
		// served, so all that is left is to say loudly that an event is lost.
		s.Metrics.eventsLost.Inc()
		s.Log.ErrorContext(ctx, "usage event lost", "request_id", ev.RequestID, "error", err)
	}
	if res.Usage.Known {
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "input").Add(float64(res.Usage.Input))
		s.Metrics.tokens.WithLabelValues(model, route.Backend.ID, "output").Add(float64(res.Usage.Output))
	}
	return outcome
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
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": typ, "code": code, "param": nil},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

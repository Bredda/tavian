// Package admin is the administration API, served on the admin listener under
// /admin/v1 (docs/ADMIN_API.md).
//
// It is the control plane of ADR-0003: separate credentials from the data
// plane, and every call that changes something is recorded with its author in
// the database and, through the outbox, in the audit chain. The record is
// written before the change takes effect, so a change that cannot be recorded
// does not happen (ADR-0005).
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/ids"
	"github.com/bredda/tavian/internal/store"
)

// Prefix is where the API lives.
const Prefix = "/admin/v1"

// Actions that are recorded.
const ActionReload = "config.reload"

// Store is what the API needs from the database.
type Store interface {
	RecordAdminChange(ctx context.Context, c store.AdminChange) error
	ListAdminChanges(ctx context.Context, limit int, before int64) ([]store.AdminChange, int64, error)
}

// Rejection is returned by a change that was refused: the configuration is
// invalid, or cannot be applied to a running gateway. Nothing changed.
type Rejection struct {
	// Code is stable and meant for programs; Message is for people and says why.
	Code, Message string
	// Status is the HTTP status to answer with (422 when empty).
	Status int
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Message }

// Record writes the record of a change that is about to take effect. A
// Reloader must call it exactly once, after validation and before it applies
// anything, and give up if it fails.
type Record func(target string, detail any) error

// Reloaded says what a reload did.
type Reloaded struct {
	Revision string `json:"revision"`
	Previous string `json:"previous"`
}

// Reloader reads the configuration file again, as SIGHUP does.
type Reloader func(ctx context.Context, record Record) (Reloaded, error)

// Deps are the dependencies of the API.
type Deps struct {
	Snap   *config.Holder
	Store  Store
	Reload Reloader
	Log    *slog.Logger
	// Observe counts calls by action and outcome, for metrics. May be nil.
	Observe func(action, outcome string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d *Deps) observe(action, outcome string) {
	if d.Observe != nil {
		d.Observe(action, outcome)
	}
}

// Enabled says whether the API is served: it needs at least one admin token.
func Enabled(snap *config.Holder) bool {
	s := snap.Load()
	return s != nil && len(s.AdminTokens) > 0
}

// Register adds the API to mux. The routes answer 404 while no admin token is
// configured.
func Register(mux *http.ServeMux, d Deps) {
	a := &api{Deps: d, auth: auth.AdminAuthenticator{Snap: d.Snap}}
	mux.HandleFunc("GET "+Prefix+"/whoami", a.handle("whoami", a.whoami))
	mux.HandleFunc("GET "+Prefix+"/config", a.handle("config.show", a.configShow))
	mux.HandleFunc("GET "+Prefix+"/changes", a.handle("changes.list", a.changes))
	mux.HandleFunc("POST "+Prefix+"/config/reload", a.handle(ActionReload, a.reload))
}

type api struct {
	Deps
	auth auth.AdminAuthenticator
}

// call is what a handler knows about the request it serves.
type call struct {
	actor     string
	requestID string
	remote    string
}

type handler func(w http.ResponseWriter, r *http.Request, c call)

// handle authenticates, then runs h. The API is invisible without tokens.
func (a *api) handle(action string, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		if !Enabled(a.Snap) {
			http.NotFound(w, r)
			return
		}
		id := r.Header.Get("X-Request-Id")
		if !ids.Valid(id) {
			id = ids.New()
		}
		hd.Set("X-Request-Id", id)
		who, err := a.auth.Authenticate(r)
		if err != nil {
			a.Log.InfoContext(r.Context(), "admin authentication failed", "reason", auth.Reason(err), "request_id", id, "remote", remoteHost(r))
			a.observe(action, "unauthenticated")
			hd.Set("WWW-Authenticate", `Bearer realm="tavian-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid admin token is required")
			return
		}
		h(w, r, call{actor: who.TokenID, requestID: id, remote: remoteHost(r)})
	}
}

func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *api) whoami(w http.ResponseWriter, _ *http.Request, c call) {
	writeJSON(w, http.StatusOK, map[string]string{"actor": c.actor, "method": "admin_token"})
}

func (a *api) configShow(w http.ResponseWriter, _ *http.Request, _ call) {
	s := a.Snap.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"revision":     s.Revision,
		"profile":      s.Profile,
		"models":       len(s.Models),
		"backends":     len(s.Backends),
		"api_keys":     len(s.Keys),
		"admin_tokens": len(s.AdminTokens),
		"policies":     len(s.PolicySources),
		"warnings":     append([]string{}, s.Warnings...),
	})
}

func (a *api) changes(w http.ResponseWriter, r *http.Request, _ call) {
	limit, before := 50, int64(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_request", "before must be a positive integer, as given by a previous page")
			return
		}
		before = n
	}
	list, next, err := a.Store.ListAdminChanges(r.Context(), limit, before)
	if err != nil {
		a.Log.ErrorContext(r.Context(), "listing admin changes failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the change history cannot be read")
		return
	}
	if list == nil {
		list = []store.AdminChange{}
	}
	out := map[string]any{"changes": list}
	if next > 0 {
		out["next"] = strconv.FormatInt(next, 10)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) reload(w http.ResponseWriter, r *http.Request, c call) {
	if a.Reload == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "this gateway cannot reload its configuration")
		return
	}
	var recordErr error
	record := func(target string, detail any) error {
		recordErr = a.recordChange(r.Context(), c, ActionReload, target, store.OutcomeApplied, detail)
		return recordErr
	}
	res, err := a.Reload(r.Context(), record)
	switch {
	case err == nil:
		a.observe(ActionReload, "applied")
		a.Log.InfoContext(r.Context(), "admin change", "action", ActionReload, "actor", c.actor, "revision", res.Revision, "request_id", c.requestID)
		writeJSON(w, http.StatusOK, res)
	case recordErr != nil:
		// The change was not recorded, so it was not made.
		a.observe(ActionReload, "audit_unavailable")
		a.Log.ErrorContext(r.Context(), "admin change refused: it cannot be recorded", "action", ActionReload, "actor", c.actor, "error", recordErr, "request_id", c.requestID)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the change cannot be recorded, so it was not made")
	default:
		var rej *Rejection
		if !errors.As(err, &rej) {
			a.observe(ActionReload, "failed")
			a.Log.ErrorContext(r.Context(), "admin change failed", "action", ActionReload, "actor", c.actor, "error", err, "request_id", c.requestID)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "the configuration could not be reloaded; the running revision is unchanged")
			return
		}
		// A refused attempt is recorded too; if that fails the refusal still
		// stands, since nothing changed.
		if rerr := a.recordChange(r.Context(), c, ActionReload, "", store.OutcomeRejected, map[string]string{"code": rej.Code}); rerr != nil {
			a.Log.ErrorContext(r.Context(), "the rejection of an admin change could not be recorded", "error", rerr, "request_id", c.requestID)
		}
		a.observe(ActionReload, "rejected")
		status := rej.Status
		if status == 0 {
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, rej.Code, rej.Message)
	}
}

func (a *api) recordChange(ctx context.Context, c call, action, target, outcome string, detail any) error {
	if a.Store == nil {
		return errors.New("no database")
	}
	var raw json.RawMessage
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		raw = b
	}
	return a.Store.RecordAdminChange(ctx, store.AdminChange{
		EventID: ids.New(), OccurredAt: a.now(), Actor: c.actor, Action: action, Target: target,
		Outcome: outcome, RequestID: c.requestID, RemoteAddr: c.remote, Detail: raw,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

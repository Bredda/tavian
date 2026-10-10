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
	"slices"
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
const (
	ActionReload   = "config.reload"
	ActionApply    = "config.apply"
	ActionRollback = "config.rollback"
)

// Store is what the API needs from the database.
type Store interface {
	RecordAdminChange(ctx context.Context, c store.AdminChange) error
	ListAdminChanges(ctx context.Context, limit int, before int64) ([]store.AdminChange, int64, error)
	GetRevision(ctx context.Context, id string) (store.StoredRevision, error)
	ListRevisions(ctx context.Context, limit int, before int64) ([]store.StoredRevision, int64, error)
	ActiveRevision(ctx context.Context) (store.Active, bool, error)
}

// Rejection is returned by a change that was refused: the configuration is
// invalid, cannot be applied to a running gateway, or is not based on the
// active revision. Nothing changed.
type Rejection struct {
	// Code is stable and meant for programs; Message is for people and says why.
	Code, Message string
	// Status is the HTTP status to answer with (422 when empty).
	Status int
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Message }

// ErrAuditUnavailable is returned by a Controller that could not record a
// change: the change was not made.
var ErrAuditUnavailable = errors.New("the change cannot be recorded")

// Actor is who asks for a change: it goes into the record of the change.
type Actor struct {
	ID        string // the admin token's id
	RequestID string
	Remote    string
}

// File is a policy file of a revision.
type File struct {
	Name string `json:"name"`
	YAML string `json:"yaml"`
}

// ApplyRequest is a configuration to validate or apply: what Load reads from
// a configuration file and its policy directory. Base is the revision the
// caller believes is active; the change is refused if it is not.
type ApplyRequest struct {
	Config   string `json:"config"`
	Policies []File `json:"policies"`
	Base     string `json:"base"`
}

// RollbackRequest asks to make an earlier revision the active one again.
type RollbackRequest struct {
	Revision string `json:"revision"`
	Base     string `json:"base"`
}

// Result says what a change did.
type Result struct {
	Revision string `json:"revision"`
	Previous string `json:"previous"`
	// Unchanged is true when the new revision is the one that was active.
	Unchanged bool     `json:"unchanged"`
	Warnings  []string `json:"warnings"`
}

// Validation is what checking a configuration found. Valid says that it
// compiles; Applicable that it could replace the running one (a setting that
// needs a restart, or the removal of every admin token, makes a valid
// configuration inapplicable, and Reason says why).
type Validation struct {
	Valid      bool     `json:"valid"`
	Applicable bool     `json:"applicable"`
	Revision   string   `json:"revision,omitempty"`
	Errors     []string `json:"errors"`
	Warnings   []string `json:"warnings"`
	Reason     string   `json:"reason,omitempty"`
}

// Controller changes the running configuration. The implementation records
// each change it makes, in the same transaction as the change of the active
// revision, and before the new configuration takes effect; one that cannot
// record it returns ErrAuditUnavailable and changes nothing. A refusal is a
// *Rejection (the caller records the attempt).
type Controller interface {
	// Reload reads the configuration file and its policy directory again.
	Reload(ctx context.Context, who Actor) (Result, error)
	// Apply makes the given configuration the active one.
	Apply(ctx context.Context, who Actor, req ApplyRequest) (Result, error)
	// Rollback makes an earlier revision the active one again.
	Rollback(ctx context.Context, who Actor, req RollbackRequest) (Result, error)
	// Validate checks a configuration without applying it.
	Validate(ctx context.Context, req ApplyRequest) Validation
}

// Deps are the dependencies of the API.
type Deps struct {
	Snap  *config.Holder
	Store Store
	// Control changes the configuration; without one the API only reads.
	Control Controller
	Log     *slog.Logger
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

// Permission is what a call needs. Roles hold permissions, routes ask for one:
// that is the only place where who may do what is decided.
type Permission string

const (
	// PermRead is for calls that only look: the running configuration, the
	// revisions, the history of changes.
	PermRead Permission = "read"
	// PermOperate is for calls that act without changing the configuration:
	// checking one, and making the gateway read its file again.
	PermOperate Permission = "operate"
	// PermChange is for calls that change the configuration.
	PermChange Permission = "change"
)

// permissions says what each role holds. A role that is not here holds nothing.
var permissions = map[config.Role][]Permission{
	config.RoleAuditor:  {PermRead},
	config.RoleOperator: {PermRead, PermOperate},
	config.RoleAdmin:    {PermRead, PermOperate, PermChange},
}

// Allows says whether a role holds a permission.
func Allows(role config.Role, p Permission) bool {
	return slices.Contains(permissions[role], p)
}

// RouteInfo describes a route of the API, for documentation and tests.
type RouteInfo struct {
	Method, Path string
	Permission   Permission
	// Mutating routes change the gateway when they succeed: a call that is
	// refused for lack of a role is recorded like any other refused change.
	Mutating bool
}

type route struct {
	RouteInfo
	action string
	h      func(*api, http.ResponseWriter, *http.Request, call)
}

// routes is every route of the API. Nothing is served that is not listed here
// with the permission it needs.
var routes = []route{
	{RouteInfo{"GET", "/whoami", PermRead, false}, "whoami", (*api).whoami},
	{RouteInfo{"GET", "/config", PermRead, false}, "config.show", (*api).configShow},
	{RouteInfo{"GET", "/changes", PermRead, false}, "changes.list", (*api).changes},
	{RouteInfo{"GET", "/config/revisions", PermRead, false}, "revisions.list", (*api).revisions},
	{RouteInfo{"GET", "/config/revisions/{id}", PermRead, false}, "revisions.show", (*api).revision},
	{RouteInfo{"GET", "/config/diff", PermRead, false}, "revisions.diff", (*api).diff},
	{RouteInfo{"POST", "/config/validate", PermOperate, false}, "config.validate", (*api).validate},
	{RouteInfo{"POST", "/config/reload", PermOperate, true}, ActionReload, (*api).reload},
	{RouteInfo{"POST", "/config/apply", PermChange, true}, ActionApply, (*api).apply},
	{RouteInfo{"POST", "/config/rollback", PermChange, true}, ActionRollback, (*api).rollback},
}

// Routes lists the routes of the API with the permission each one needs.
func Routes() []RouteInfo {
	out := make([]RouteInfo, 0, len(routes))
	for _, r := range routes {
		out = append(out, RouteInfo{r.Method, Prefix + r.Path, r.Permission, r.Mutating})
	}
	return out
}

// Register adds the API to mux. The routes answer 404 while no admin token is
// configured.
func Register(mux *http.ServeMux, d Deps) {
	a := &api{Deps: d, auth: auth.AdminAuthenticator{Snap: d.Snap}}
	for _, r := range routes {
		mux.HandleFunc(r.Method+" "+Prefix+r.Path, a.handle(r, func(w http.ResponseWriter, req *http.Request, c call) { r.h(a, w, req, c) }))
	}
}

type api struct {
	Deps
	auth auth.AdminAuthenticator
}

// call is what a handler knows about the request it serves.
type call struct {
	actor     string
	role      config.Role
	requestID string
	remote    string
}

type handler func(w http.ResponseWriter, r *http.Request, c call)

// handle authenticates, checks the role, then runs h. The API is invisible
// without tokens.
func (a *api) handle(rt route, h handler) http.HandlerFunc {
	action := rt.action
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
		c := call{actor: who.TokenID, role: who.Role, requestID: id, remote: remoteHost(r)}
		if !Allows(who.Role, rt.Permission) {
			a.forbid(w, r, c, rt)
			return
		}
		h(w, r, c)
	}
}

// forbid answers a call whose token lacks the permission. An attempt to change
// something is recorded, like any other refused change.
func (a *api) forbid(w http.ResponseWriter, r *http.Request, c call, rt route) {
	a.Log.InfoContext(r.Context(), "admin call refused: the role is not enough", "action", rt.action, "actor", c.actor,
		"role", string(c.role), "needs", string(rt.Permission), "request_id", c.requestID)
	a.observe(rt.action, "forbidden")
	if rt.Mutating && a.Store != nil {
		if err := a.recordChange(r.Context(), c, rt.action, "", store.OutcomeRejected, map[string]string{"code": "forbidden", "role": string(c.role)}); err != nil {
			a.Log.ErrorContext(r.Context(), "the refusal of an admin change could not be recorded", "error", err, "request_id", c.requestID)
		}
	}
	writeError(w, http.StatusForbidden, "forbidden", "this call needs the permission "+string(rt.Permission)+", which the role "+string(c.role)+" of your token does not hold")
}

func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *api) whoami(w http.ResponseWriter, _ *http.Request, c call) {
	writeJSON(w, http.StatusOK, map[string]string{"actor": c.actor, "method": "admin_token", "role": string(c.role)})
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
	limit, before, ok := paging(w, r)
	if !ok {
		return
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

// change runs a change of the configuration and answers for it. The
// controller records what it applies; here a refused attempt is recorded and
// the failures are told apart.
func (a *api) change(w http.ResponseWriter, r *http.Request, c call, action, target string, run func(Actor) (Result, error)) {
	res, err := run(Actor{ID: c.actor, RequestID: c.requestID, Remote: c.remote})
	var rej *Rejection
	switch {
	case err == nil:
		a.observe(action, "applied")
		a.Log.InfoContext(r.Context(), "admin change", "action", action, "actor", c.actor, "revision", res.Revision, "request_id", c.requestID)
		if res.Warnings == nil {
			res.Warnings = []string{}
		}
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, ErrAuditUnavailable):
		// The change was not recorded, so it was not made.
		a.observe(action, "audit_unavailable")
		a.Log.ErrorContext(r.Context(), "admin change refused: it cannot be recorded", "action", action, "actor", c.actor, "error", err, "request_id", c.requestID)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the change cannot be recorded, so it was not made")
	case errors.As(err, &rej):
		// A refused attempt is recorded too; if that fails the refusal still
		// stands, since nothing changed.
		if rerr := a.recordChange(r.Context(), c, action, target, store.OutcomeRejected, map[string]string{"code": rej.Code}); rerr != nil {
			a.Log.ErrorContext(r.Context(), "the rejection of an admin change could not be recorded", "error", rerr, "request_id", c.requestID)
		}
		a.observe(action, "rejected")
		status := rej.Status
		if status == 0 {
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, rej.Code, rej.Message)
	default:
		a.observe(action, "failed")
		a.Log.ErrorContext(r.Context(), "admin change failed", "action", action, "actor", c.actor, "error", err, "request_id", c.requestID)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the change could not be made; the running revision is unchanged")
	}
}

// maxBody bounds what a change may send: a configuration and its policy files.
const maxBody = 8 << 20

// decode reads a JSON body strictly. It answers the error itself and says
// whether the body was usable.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request is larger than "+strconv.Itoa(maxBody>>20)+" MiB")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields: "+err.Error())
		return false
	}
	return true
}

// canChange answers 501 when no controller was given, and says so.
func (a *api) canChange(w http.ResponseWriter) bool {
	if a.Control == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "this gateway cannot change its configuration")
		return false
	}
	return true
}

func (a *api) reload(w http.ResponseWriter, r *http.Request, c call) {
	if !a.canChange(w) {
		return
	}
	a.change(w, r, c, ActionReload, "", func(who Actor) (Result, error) { return a.Control.Reload(r.Context(), who) })
}

func (a *api) apply(w http.ResponseWriter, r *http.Request, c call) {
	if !a.canChange(w) {
		return
	}
	var req ApplyRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Base == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "base is required: the revision you believe is active (GET /admin/v1/config)")
		return
	}
	a.change(w, r, c, ActionApply, "", func(who Actor) (Result, error) { return a.Control.Apply(r.Context(), who, req) })
}

func (a *api) rollback(w http.ResponseWriter, r *http.Request, c call) {
	if !a.canChange(w) {
		return
	}
	var req RollbackRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Base == "" || !revisionID.MatchString(req.Revision) {
		writeError(w, http.StatusBadRequest, "invalid_request", "revision (12 hexadecimal characters) and base (the revision you believe is active) are required")
		return
	}
	a.change(w, r, c, ActionRollback, req.Revision, func(who Actor) (Result, error) { return a.Control.Rollback(r.Context(), who, req) })
}

func (a *api) validate(w http.ResponseWriter, r *http.Request, _ call) {
	if !a.canChange(w) {
		return
	}
	var req ApplyRequest
	if !decode(w, r, &req) {
		return
	}
	v := a.Control.Validate(r.Context(), req)
	if v.Errors == nil {
		v.Errors = []string{}
	}
	if v.Warnings == nil {
		v.Warnings = []string{}
	}
	writeJSON(w, http.StatusOK, v)
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

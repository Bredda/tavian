package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bredda/tavian/internal/admin"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/ids"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/quota"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/version"
)

// Actions recorded besides the ones of the administration API.
const (
	actionBootstrap = "config.bootstrap"
	actorStartup    = "startup"
	actorSighup     = "sighup"
)

// controller changes the running configuration for SIGHUP, for the
// administration API and at startup. One change runs at a time. Every change
// moves the active revision in the database, with the record of who made it,
// in one transaction, before the new configuration takes effect.
type controller struct {
	mu   sync.Mutex
	log  *slog.Logger
	path string // the configuration file the gateway started with
	// running is the configuration of that start: a setting that needs a
	// restart cannot differ from it.
	running *config.Config
	holder  *config.Holder
	st      *store.Store
	qs      *quota.Store
	now     func() time.Time
}

func (c *controller) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

// candidate is a configuration that compiled and can replace the running one.
type candidate struct {
	raw  []byte
	snap *config.Snapshot
}

func reject(code, format string, args ...any) *admin.Rejection {
	return &admin.Rejection{Code: code, Message: fmt.Sprintf(format, args...)}
}

// conflicting is a refusal because the active revision is not the expected one.
func conflicting(format string, args ...any) *admin.Rejection {
	return &admin.Rejection{Code: "conflict", Message: fmt.Sprintf(format, args...), Status: http.StatusConflict}
}

// build compiles a configuration and checks that it can replace the running
// one: nothing in it needs a restart, and the administration API keeps at
// least one admin token (a configuration without one would lock everyone out
// of changing it).
func (c *controller) build(cfg *config.Config, raw []byte) (*candidate, error) {
	if err := restartRequired(c.running, cfg); err != nil {
		return nil, &admin.Rejection{Code: "restart_required", Message: err.Error(), Status: http.StatusConflict}
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		return nil, reject("invalid_configuration", "%s", err)
	}
	if !snap.HasLiveAdmin(c.clock()) {
		return nil, noAdminToken()
	}
	return &candidate{raw: raw, snap: snap}, nil
}

func noAdminToken() *admin.Rejection {
	return reject("no_admin_token", "the configuration has no admin token with the role admin that has not expired: nobody could change the configuration through the administration API afterwards")
}

// fromBytes reads a configuration given as bytes, the way Load reads a file.
func (c *controller) fromBytes(raw []byte, policies []policy.Source) (*config.Config, error) {
	cfg, err := config.FromRevision(raw, policies, filepath.Dir(c.path))
	if err != nil {
		return nil, reject("invalid_configuration", "%s", err)
	}
	return cfg, nil
}

func sources(files []admin.File) []policy.Source {
	out := make([]policy.Source, 0, len(files))
	for _, f := range files {
		out = append(out, policy.Source{Name: f.Name, Raw: []byte(f.YAML)})
	}
	return out
}

// activate makes cand the running configuration. base is the revision the
// caller believes is active in the database; fileRevision is set when the
// change comes from the configuration file.
func (c *controller) activate(ctx context.Context, who admin.Actor, action string, cand *candidate, base, fileRevision string, detail map[string]any) (admin.Result, error) {
	previous := c.holder.Load().Revision
	snap := cand.snap
	if c.st != nil {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if c.qs != nil {
			// a policy added now may limit a scope that has been using tokens all day
			if err := seedQuotas(rctx, c.log, c.st, c.qs, snap); err != nil {
				return admin.Result{}, err
			}
		}
		var policies []byte
		if len(snap.PolicySources) > 0 {
			var err error
			if policies, err = json.Marshal(snap.PolicySources); err != nil {
				return admin.Result{}, fmt.Errorf("encode policies: %w", err)
			}
		}
		if detail == nil {
			detail = map[string]any{}
		}
		detail["previous"] = previous
		detail["unchanged"] = previous == snap.Revision
		raw, err := json.Marshal(detail)
		if err != nil {
			return admin.Result{}, err
		}
		err = c.st.Activate(rctx, store.Activation{
			Revision: store.Revision{ID: snap.Revision, Profile: string(snap.Profile), YAML: cand.raw, Version: version.String(), Policies: policies},
			Base:     base, FileRevision: fileRevision,
			Change: store.AdminChange{
				EventID: ids.New(), OccurredAt: c.clock(), Actor: who.ID, Action: action, Target: snap.Revision,
				Outcome: store.OutcomeApplied, RequestID: who.RequestID, RemoteAddr: who.Remote, Detail: raw,
			},
		})
		switch {
		case errors.Is(err, store.ErrConflict):
			return admin.Result{}, c.conflict(rctx, base)
		case err != nil:
			return admin.Result{}, fmt.Errorf("%w: %w", admin.ErrAuditUnavailable, err)
		}
	}
	c.holder.Store(snap)
	logKeyExpiries(c.log, snap, time.Now())
	logAdminTokenExpiries(c.log, snap, time.Now())
	logInspection(c.log, snap)
	logPolicies(c.log, snap)
	c.log.Info("configuration changed", "action", action, "actor", who.ID, "revision", snap.Revision, "previous", previous,
		"backends", len(snap.Backends), "models", len(snap.Models))
	return admin.Result{Revision: snap.Revision, Previous: previous, Unchanged: previous == snap.Revision, Warnings: snap.Warnings}, nil
}

// conflict says what the active revision is instead of the expected one.
func (c *controller) conflict(ctx context.Context, base string) error {
	act, ok, err := c.st.ActiveRevision(ctx)
	switch {
	case err != nil:
		return conflicting("the active revision is not %s any more: read it again (GET /admin/v1/config/revisions/active)", base)
	case !ok:
		return conflicting("no revision is active yet: the base must be empty")
	}
	return conflicting("the active revision is %s, not %s: someone changed it, read it again and decide", act.Revision, base)
}

// activeBase is the revision the database says is active, "" when none is.
func (c *controller) activeBase(ctx context.Context) (string, error) {
	if c.st == nil {
		return "", nil
	}
	act, ok, err := c.st.ActiveRevision(ctx)
	if err != nil || !ok {
		return "", err
	}
	return act.Revision, nil
}

// Reload reads the configuration file and its policy directory again.
func (c *controller) Reload(ctx context.Context, who admin.Actor) (admin.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, raw, err := config.Load(c.path)
	if err != nil {
		return admin.Result{}, reject("invalid_configuration", "%s", err)
	}
	cand, err := c.build(cfg, raw)
	if err != nil {
		return admin.Result{}, err
	}
	base, err := c.activeBase(ctx)
	if err != nil {
		return admin.Result{}, err
	}
	return c.activate(ctx, who, admin.ActionReload, cand, base, cand.snap.Revision, map[string]any{"source": "file"})
}

// Apply makes the given configuration the active one.
func (c *controller) Apply(ctx context.Context, who admin.Actor, req admin.ApplyRequest) (admin.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, err := c.fromBytes([]byte(req.Config), sources(req.Policies))
	if err != nil {
		return admin.Result{}, err
	}
	cand, err := c.build(cfg, []byte(req.Config))
	if err != nil {
		return admin.Result{}, err
	}
	return c.activate(ctx, who, admin.ActionApply, cand, req.Base, "", map[string]any{"base": req.Base})
}

// Rollback makes an earlier revision the active one again, unless that would
// bring back a credential that has been removed since.
func (c *controller) Rollback(ctx context.Context, who admin.Actor, req admin.RollbackRequest) (admin.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return admin.Result{}, errors.New("no database")
	}
	rev, err := c.st.GetRevision(ctx, req.Revision)
	if errors.Is(err, store.ErrNotFound) {
		return admin.Result{}, &admin.Rejection{Code: "not_found", Message: "no such revision: " + req.Revision, Status: http.StatusNotFound}
	}
	if err != nil {
		return admin.Result{}, err
	}
	var stored []policy.Source
	if len(rev.Policies) > 0 {
		if err := json.Unmarshal(rev.Policies, &stored); err != nil {
			return admin.Result{}, fmt.Errorf("revision %s: %w", rev.ID, err)
		}
	}
	cfg, err := c.fromBytes(rev.YAML, stored)
	if err != nil {
		return admin.Result{}, err
	}
	cand, err := c.build(cfg, rev.YAML)
	if err != nil {
		return admin.Result{}, err
	}
	if back := credentialsAdded(c.holder.Load(), cand.snap); len(back) > 0 {
		return admin.Result{}, &admin.Rejection{
			Code: "credentials_would_return", Status: http.StatusConflict,
			Message: "revision " + rev.ID + " holds credentials that are not in the running configuration, and may have been revoked since: " +
				strings.Join(back, ", ") + ". Apply a configuration that lists exactly the ones you want instead.",
		}
	}
	return c.activate(ctx, who, admin.ActionRollback, cand, req.Base, "", map[string]any{"base": req.Base, "to": rev.ID})
}

// credentialsAdded names the API keys and admin tokens that target has and
// current does not.
func credentialsAdded(current, target *config.Snapshot) []string {
	var out []string
	for h, k := range target.Keys {
		if _, ok := current.Keys[h]; !ok {
			out = append(out, "API key "+k.ID)
		}
	}
	for h, t := range target.AdminTokens {
		if _, ok := current.AdminTokens[h]; !ok {
			out = append(out, "admin token "+t.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Validate checks a configuration without applying it.
func (c *controller) Validate(_ context.Context, req admin.ApplyRequest) admin.Validation {
	cfg, err := config.FromRevision([]byte(req.Config), sources(req.Policies), filepath.Dir(c.path))
	if err != nil {
		return admin.Validation{Errors: lines(err)}
	}
	snap, err := config.Compile(cfg, []byte(req.Config), os.Getenv)
	if err != nil {
		return admin.Validation{Errors: lines(err)}
	}
	v := admin.Validation{Valid: true, Applicable: true, Revision: snap.Revision, Warnings: snap.Warnings}
	switch err := restartRequired(c.running, cfg); {
	case err != nil:
		v.Applicable, v.Reason = false, "restart_required: "+err.Error()
	case !snap.HasLiveAdmin(c.clock()):
		v.Applicable, v.Reason = false, "no_admin_token: "+noAdminToken().Message
	}
	return v
}

// lines splits an error that joins several into one message each.
func lines(err error) []string {
	var out []string
	for _, l := range strings.Split(err.Error(), "\n") {
		if l = strings.TrimSpace(l); l != "" && l != "invalid configuration:" {
			out = append(out, l)
		}
	}
	return out
}

// sighup is the reload that SIGHUP asks for. It leaves the same trace as the
// administration API, under the actor "sighup".
func (c *controller) sighup(ctx context.Context) {
	_, err := c.Reload(ctx, admin.Actor{ID: actorSighup})
	if err == nil {
		return
	}
	var rej *admin.Rejection
	if errors.As(err, &rej) && c.st != nil {
		// a refused attempt is recorded too
		raw, _ := json.Marshal(map[string]string{"code": rej.Code})
		rerr := c.st.RecordAdminChange(ctx, store.AdminChange{
			EventID: ids.New(), OccurredAt: c.clock(), Actor: actorSighup, Action: admin.ActionReload,
			Outcome: store.OutcomeRejected, Detail: raw,
		})
		if rerr != nil {
			c.log.Error("the rejection of a reload could not be recorded", "error", rerr)
		}
	}
	c.log.Error("configuration reload rejected, keeping current revision",
		"current", c.holder.Load().Revision, "error", err)
}

// restartRequired says why a configuration cannot replace the running one
// without a restart; nil when it can.
func restartRequired(running, cfg *config.Config) error {
	switch {
	case cfg.Profile != running.Profile:
		return fmt.Errorf("profile changed from %q to %q: restart required", running.Profile, cfg.Profile)
	case cfg.Database != running.Database:
		return errors.New("database settings changed: restart required")
	case cfg.Audit != running.Audit || cfg.Workers != running.Workers || !reflect.DeepEqual(cfg.Outbox, running.Outbox):
		return errors.New("audit, workers or outbox settings changed: restart required")
	case cfg.Admin.UseFlushEvery != running.Admin.UseFlushEvery:
		return errors.New("admin.use_flush_every changed: restart required")
	case !sameOIDCConnection(cfg.OIDC, running.OIDC):
		return errors.New("oidc settings other than mappings changed: restart required")
	}
	return nil
}

// startupSnapshot decides which configuration the gateway runs at start when
// the administration API is on (docs/ADMIN_API.md): the configuration file
// when it changed since the last start, otherwise the revision that is active
// in the database, so that what the API applied survives a restart. It
// records what it decides. file is what the file compiled to.
func (c *controller) startupSnapshot(ctx context.Context, file *config.Snapshot, raw []byte) (*config.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileCand := &candidate{raw: raw, snap: file}
	who := admin.Actor{ID: actorStartup}
	act, ok, err := c.st.ActiveRevision(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case !ok:
		_, err = c.activate(ctx, who, actionBootstrap, fileCand, "", file.Revision, map[string]any{"reason": "first start with the administration API"})
		return file, bootstrapError(err)
	case act.FileRevision != file.Revision:
		_, err = c.activate(ctx, who, actionBootstrap, fileCand, act.Revision, file.Revision,
			map[string]any{"reason": "the configuration file changed since the last start", "active": act.Revision})
		return file, bootstrapError(err)
	case act.Revision == file.Revision:
		return file, nil
	}
	rev, err := c.st.GetRevision(ctx, act.Revision)
	if err != nil {
		return nil, fmt.Errorf("the active revision %s cannot be read: %w", act.Revision, err)
	}
	var stored []policy.Source
	if len(rev.Policies) > 0 {
		if err := json.Unmarshal(rev.Policies, &stored); err != nil {
			return nil, fmt.Errorf("the active revision %s has unreadable policies: %w", act.Revision, err)
		}
	}
	cfg, err := config.FromRevision(rev.YAML, stored, filepath.Dir(c.path))
	if err == nil {
		err = restartRequired(c.running, cfg)
	}
	var snap *config.Snapshot
	if err == nil {
		snap, err = config.Compile(cfg, rev.YAML, os.Getenv)
	}
	if err != nil {
		return nil, fmt.Errorf("the active revision %s (applied through the administration API) cannot run with this configuration file: %w\n"+
			"edit the configuration file to match it, or change it so that the file is the one to follow, then start again", act.Revision, err)
	}
	c.log.Info("resuming the active configuration revision applied through the administration API", "revision", snap.Revision, "file", file.Revision)
	return snap, nil
}

func bootstrapError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("recording the configuration at startup: %w", err)
}

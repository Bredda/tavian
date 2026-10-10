package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/admin"
	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/chain"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

// These tests need a PostgreSQL: see internal/store/storetest.

type ctlEnv struct {
	t       *testing.T
	st      *store.Store
	ctl     *controller
	holder  *config.Holder
	path    string
	keyHash string
	admHash string
}

// configYAML is a valid configuration with one API key, the given admin
// tokens (ids "ops" and, when more is true, "second") and extra top-level YAML.
func (e *ctlEnv) configYAML(extra string, adminTokens ...string) string {
	body := `profile: air-gapped
database: {url_env: TAVIAN_CTL_DB}
backends:
  - {id: local, type: openai, base_url: "http://127.0.0.1:9/v1", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: local}]}
api_keys:
  - {id: dev, hash: "` + e.keyHash + `", team: t, application: a, allowed_models: ["*"]}
` + extra
	if len(adminTokens) == 0 {
		adminTokens = []string{"ops"}
	}
	body += "admin:\n  tokens:\n"
	for _, id := range adminTokens {
		hash := e.admHash
		if id != "ops" {
			_, hash, _ = auth.GenerateAdminToken()
		}
		body += `    - {id: ` + id + `, role: admin, hash: "` + hash + `"}` + "\n"
	}
	return body
}

func (e *ctlEnv) write(yaml string) {
	e.t.Helper()
	if err := os.WriteFile(e.path, []byte(yaml), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// newCtlEnv starts a controller as the gateway would: from the file, with the
// file's revision bootstrapped as the active one.
func newCtlEnv(t *testing.T) *ctlEnv {
	t.Helper()
	st, url := storetest.New(t)
	t.Setenv("TAVIAN_CTL_DB", url)
	e := &ctlEnv{t: t, st: st, path: filepath.Join(t.TempDir(), "tavian.yaml")}
	_, e.keyHash, _ = auth.GenerateKey()
	_, e.admHash, _ = auth.GenerateAdminToken()
	e.write(e.configYAML(""))
	cfg, raw, err := config.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	e.holder = &config.Holder{}
	e.holder.Store(snap)
	e.ctl = &controller{log: slog.New(slog.DiscardHandler), path: e.path, running: cfg, holder: e.holder, st: st}
	got, err := e.ctl.startupSnapshot(context.Background(), snap, raw)
	if err != nil || got != snap {
		t.Fatalf("bootstrap: %v (same snapshot: %v)", err, got == snap)
	}
	return e
}

func (e *ctlEnv) active() store.Active {
	e.t.Helper()
	a, ok, err := e.st.ActiveRevision(context.Background())
	if err != nil || !ok {
		e.t.Fatalf("active revision: %v %v", ok, err)
	}
	return a
}

func (e *ctlEnv) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.st.Pool().QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *ctlEnv) rejection(err error) *admin.Rejection {
	e.t.Helper()
	var rej *admin.Rejection
	if !errors.As(err, &rej) {
		e.t.Fatalf("err = %v, want a rejection", err)
	}
	return rej
}

var bg = context.Background()

func who(id string) admin.Actor {
	return admin.Actor{ID: id, RequestID: "req-12345678", Remote: "10.1.2.3"}
}

func TestStartupBootstrapsTheFirstRevision(t *testing.T) {
	e := newCtlEnv(t)
	a := e.active()
	if a.Revision != e.holder.Load().Revision || a.FileRevision != a.Revision || a.ActivatedBy != "startup" {
		t.Errorf("active = %+v", a)
	}
	if n := e.count(`SELECT count(*) FROM admin_changes WHERE action = 'config.bootstrap' AND actor = 'startup' AND outcome = 'applied'`); n != 1 {
		t.Errorf("bootstrap records = %d", n)
	}
	if n := e.count(`SELECT count(*) FROM outbox WHERE kind = 'admin_change'`); n != 1 {
		t.Errorf("outbox events = %d", n)
	}
}

func TestReloadActivatesTheFileAndRecordsWho(t *testing.T) {
	e := newCtlEnv(t)
	before := e.holder.Load().Revision
	e.write(e.configYAML("log: {level: debug}\n"))
	res, err := e.ctl.Reload(bg, who("ops"))
	if err != nil {
		t.Fatal(err)
	}
	now := e.holder.Load().Revision
	if now == before || res.Revision != now || res.Previous != before || res.Unchanged {
		t.Fatalf("result %+v, running %q (was %q)", res, now, before)
	}
	a := e.active()
	if a.Revision != now || a.FileRevision != now || a.ActivatedBy != "ops" {
		t.Errorf("active = %+v", a)
	}
	var actor, action, target, outcome, request, remote, detail string
	if err := e.st.Pool().QueryRow(bg, `SELECT actor, action, target, outcome, request_id, remote_addr, detail::text FROM admin_changes WHERE action = 'config.reload'`).
		Scan(&actor, &action, &target, &outcome, &request, &remote, &detail); err != nil {
		t.Fatal(err)
	}
	if actor != "ops" || target != now || outcome != "applied" || request != "req-12345678" || remote != "10.1.2.3" ||
		!strings.Contains(detail, before) || !strings.Contains(detail, `"source": "file"`) {
		t.Errorf("record = %s %s %s %s %s %s %s", actor, action, target, outcome, request, remote, detail)
	}
	// reloading what is already running is recorded and changes nothing
	res, err = e.ctl.Reload(bg, who("ops"))
	if err != nil || !res.Unchanged || res.Revision != now {
		t.Errorf("second reload: %+v %v", res, err)
	}
	var again string
	if err := e.st.Pool().QueryRow(bg, `SELECT detail::text FROM admin_changes WHERE action = 'config.reload' ORDER BY seq DESC LIMIT 1`).Scan(&again); err != nil ||
		!strings.Contains(again, `"unchanged": true`) {
		t.Errorf("the record of an unchanged reload says %s (%v)", again, err)
	}
}

func TestReloadRefusesWhatCannotRun(t *testing.T) {
	e := newCtlEnv(t)
	running := e.holder.Load()
	records := e.count(`SELECT count(*) FROM admin_changes`)
	for name, c := range map[string]struct{ yaml, code string }{
		"invalid":        {e.configYAML("limits: {max_inflight: -1}\n"), "invalid_configuration"},
		"unknown field":  {e.configYAML("bogus: 1\n"), "invalid_configuration"},
		"restart":        {strings.Replace(e.configYAML(""), "TAVIAN_CTL_DB", "OTHER_ENV", 1), "restart_required"},
		"no admin token": {strings.Split(e.configYAML(""), "admin:")[0], "no_admin_token"},
	} {
		e.write(c.yaml)
		_, err := e.ctl.Reload(bg, who("ops"))
		if rej := e.rejection(err); rej.Code != c.code {
			t.Errorf("%s: code %q (%s), want %q", name, rej.Code, rej.Message, c.code)
		}
		if e.holder.Load() != running {
			t.Errorf("%s: the running configuration changed", name)
		}
	}
	if e.rejection(func() error {
		e.write(strings.Replace(e.configYAML(""), "TAVIAN_CTL_DB", "OTHER_ENV", 1))
		_, err := e.ctl.Reload(bg, who("x"))
		return err
	}()).Status != http.StatusConflict {
		t.Error("restart_required is a conflict (409)")
	}
	if e.count(`SELECT count(*) FROM admin_changes`) != records || e.active().Revision != running.Revision {
		t.Error("a refused reload changed the database")
	}
}

func TestApplyNeedsTheRightBase(t *testing.T) {
	e := newCtlEnv(t)
	base := e.holder.Load().Revision
	req := admin.ApplyRequest{Config: e.configYAML("log: {level: debug}\n"), Base: base}
	res, err := e.ctl.Apply(bg, who("ops"), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Previous != base || res.Revision == base || e.holder.Load().Revision != res.Revision {
		t.Fatalf("result %+v", res)
	}
	if a := e.active(); a.Revision != res.Revision || a.FileRevision != base || a.ActivatedBy != "ops" {
		t.Errorf("active = %+v: an API change leaves the file revision alone", a)
	}

	// the same base again is stale now
	running, records := e.holder.Load(), e.count(`SELECT count(*) FROM admin_changes`)
	req.Config = e.configYAML("log: {level: warn}\n")
	_, err = e.ctl.Apply(bg, who("bob"), req)
	rej := e.rejection(err)
	if rej.Code != "conflict" || rej.Status != http.StatusConflict || !strings.Contains(rej.Message, res.Revision) {
		t.Errorf("stale base: %+v", rej)
	}
	if e.holder.Load() != running || e.count(`SELECT count(*) FROM admin_changes`) != records {
		t.Error("a conflicting apply changed something")
	}
	if n := e.count(`SELECT count(*) FROM config_revisions`); n != 2 {
		t.Errorf("%d revisions, the refused one must not be kept", n)
	}
}

func TestApplyUsesThePoliciesOfTheRequest(t *testing.T) {
	e := newCtlEnv(t)
	base := e.holder.Load().Revision
	pol := `apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: e2e }
spec:
  scope: { team: t }
  quotas:
    - { dimension: tokens_per_day, limit: 100 }
`
	res, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML(""), Policies: []admin.File{{Name: "10-q.yaml", YAML: pol}}, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	snap := e.holder.Load()
	if len(snap.PolicySources) != 1 || snap.PolicySources[0].Name != "10-q.yaml" || res.Revision != snap.Revision {
		t.Fatalf("policy sources = %+v", snap.PolicySources)
	}
	rev, err := e.st.GetRevision(bg, res.Revision)
	if err != nil || !strings.Contains(string(rev.Policies), "10-q.yaml") {
		t.Errorf("stored revision: %+v %v", rev, err)
	}
	for name, files := range map[string][]admin.File{
		"a path":    {{Name: "../x.yaml", YAML: pol}},
		"bad yaml":  {{Name: "a.yaml", YAML: "kind: [unclosed"}},
		"duplicate": {{Name: "a.yaml", YAML: pol}, {Name: "a.yaml", YAML: pol}},
	} {
		_, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML(""), Policies: files, Base: res.Revision})
		if rej := e.rejection(err); rej.Code != "invalid_configuration" {
			t.Errorf("%s: %+v", name, rej)
		}
	}
	// the file's own policy.dir is not read for an applied revision
	_, err = e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("policy: {dir: /nonexistent}\n"), Base: res.Revision})
	if err != nil {
		t.Errorf("an applied configuration reads no policy directory: %v", err)
	}
}

func TestApplyCannotLockEveryoneOut(t *testing.T) {
	e := newCtlEnv(t)
	base := e.holder.Load().Revision
	_, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: strings.Split(e.configYAML(""), "admin:")[0], Base: base})
	if rej := e.rejection(err); rej.Code != "no_admin_token" {
		t.Errorf("%+v", rej)
	}
	// replacing the tokens is fine as long as one remains
	if _, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("", "second"), Base: base}); err != nil {
		t.Errorf("replacing the admin tokens: %v", err)
	}
}

func TestApplyKeepsAnAdminToken(t *testing.T) {
	e := newCtlEnv(t)
	base := e.holder.Load().Revision
	// tokens remain, but none of them may change the configuration
	onlyAuditors := strings.Replace(e.configYAML(""), "role: admin", "role: auditor", 1)
	_, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: onlyAuditors, Base: base})
	if rej := e.rejection(err); rej.Code != "invalid_configuration" || !strings.Contains(rej.Message, "the role admin") {
		t.Errorf("only an auditor left: %+v", rej)
	}
	// giving the role away is fine as long as another admin stays
	two := strings.Replace(e.configYAML("", "ops", "second"), "{id: ops, role: admin", "{id: ops, role: operator", 1)
	if _, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: two, Base: base}); err != nil {
		t.Errorf("an operator and another admin: %v", err)
	}
	if v := e.ctl.Validate(bg, admin.ApplyRequest{Config: onlyAuditors}); v.Valid {
		t.Errorf("validate accepts a configuration nobody could change: %+v", v)
	}
}

func TestApplyOfASettingThatNeedsARestart(t *testing.T) {
	e := newCtlEnv(t)
	_, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: strings.Replace(e.configYAML(""), "air-gapped", "open-egress", 1), Base: e.holder.Load().Revision})
	if rej := e.rejection(err); rej.Code != "restart_required" || rej.Status != http.StatusConflict || !strings.Contains(rej.Message, "profile") {
		t.Errorf("%+v", rej)
	}
}

func TestARelativeKeyPathIsTheSameAsTheFilesOne(t *testing.T) {
	// a revision that says audit.signing_key_file: k must not look like a
	// change of the audit settings when the file said the same
	e := newCtlEnv(t)
	dir := filepath.Dir(e.path)
	if _, err := chain.GenerateKeyFile(filepath.Join(dir, "audit.key")); err != nil {
		t.Fatal(err)
	}
	e.write(e.configYAML("audit: {signing_key_file: audit.key}\n"))
	cfg, raw, err := config.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	e.ctl.running = cfg
	snap, _ := config.Compile(cfg, raw, os.Getenv)
	e.holder.Store(snap)
	_, err = e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("audit: {signing_key_file: audit.key}\nlog: {level: debug}\n"), Base: e.active().Revision})
	if err != nil {
		t.Errorf("the same relative key path was taken for a change: %v", err)
	}
}

func TestRollbackReturnsToAnEarlierRevision(t *testing.T) {
	e := newCtlEnv(t)
	first := e.holder.Load().Revision
	b, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("log: {level: debug}\n"), Base: first})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.ctl.Rollback(bg, who("bob"), admin.RollbackRequest{Revision: first, Base: b.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != first || res.Previous != b.Revision || e.holder.Load().Revision != first || e.active().Revision != first || e.active().ActivatedBy != "bob" {
		t.Errorf("result %+v active %+v", res, e.active())
	}
	var action, target, detail string
	if err := e.st.Pool().QueryRow(bg, `SELECT action, target, detail::text FROM admin_changes WHERE actor = 'bob'`).Scan(&action, &target, &detail); err != nil ||
		action != "config.rollback" || target != first || !strings.Contains(detail, b.Revision) {
		t.Errorf("record: %s %s %s (%v)", action, target, detail, err)
	}
	// a rollback is not a change of the file: the revision of the file stays
	c, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("log: {level: warn}\n"), Base: first})
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("log: {level: error}\n"), Base: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ctl.Rollback(bg, who("ops"), admin.RollbackRequest{Revision: c.Revision, Base: d.Revision}); err != nil {
		t.Fatal(err)
	}
	if a := e.active(); a.Revision != c.Revision || a.FileRevision != first {
		t.Errorf("after a rollback: %+v, the file revision should still be %s", a, first)
	}
	if _, err := e.ctl.Rollback(bg, who("bob"), admin.RollbackRequest{Revision: "ffffffffffff", Base: c.Revision}); e.rejection(err).Status != http.StatusNotFound {
		t.Errorf("unknown revision: %v", err)
	}
	if _, err := e.ctl.Rollback(bg, who("bob"), admin.RollbackRequest{Revision: b.Revision, Base: first}); e.rejection(err).Code != "conflict" {
		t.Errorf("stale base: %v", err)
	}
}

func TestRollbackNeverBringsBackACredential(t *testing.T) {
	e := newCtlEnv(t)
	first := e.holder.Load().Revision
	// a second API key, then its revocation
	_, otherHash, _ := auth.GenerateKey()
	withKey := e.configYAML("") + ""
	withKey = strings.Replace(withKey, "api_keys:\n", "api_keys:\n  - {id: leaked, hash: \""+otherHash+"\", team: t, application: a, allowed_models: [\"*\"]}\n", 1)
	a, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: withKey, Base: first})
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML(""), Base: a.Revision})
	if err != nil {
		t.Fatal(err)
	}
	running := e.holder.Load()
	_, err = e.ctl.Rollback(bg, who("ops"), admin.RollbackRequest{Revision: a.Revision, Base: b.Revision})
	rej := e.rejection(err)
	if rej.Code != "credentials_would_return" || !strings.Contains(rej.Message, "API key leaked") || strings.Contains(rej.Message, otherHash) {
		t.Errorf("%+v", rej)
	}
	if e.holder.Load() != running || e.active().Revision != b.Revision {
		t.Error("the rollback went through")
	}
	// an admin token too
	withTok := e.configYAML("", "ops", "extra")
	c, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: withTok, Base: b.Revision})
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML(""), Base: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ctl.Rollback(bg, who("ops"), admin.RollbackRequest{Revision: c.Revision, Base: d.Revision}); !strings.Contains(e.rejection(err).Message, "admin token extra") {
		t.Errorf("admin token: %v", err)
	}
	// a rollback that removes credentials is fine
	if _, err := e.ctl.Rollback(bg, who("ops"), admin.RollbackRequest{Revision: first, Base: d.Revision}); err != nil {
		t.Errorf("rolling back to a revision whose credentials are all still there: %v", err)
	}
}

func TestValidateReportsWithoutChangingAnything(t *testing.T) {
	e := newCtlEnv(t)
	running, records := e.holder.Load(), e.count(`SELECT count(*) FROM admin_changes`)
	v := e.ctl.Validate(bg, admin.ApplyRequest{Config: e.configYAML("log: {level: debug}\n")})
	if !v.Valid || !v.Applicable || v.Revision == "" || v.Revision == running.Revision || len(v.Errors) != 0 {
		t.Errorf("valid: %+v", v)
	}
	v = e.ctl.Validate(bg, admin.ApplyRequest{Config: strings.Split(e.configYAML(""), "admin:")[0]})
	if !v.Valid || v.Applicable || !strings.HasPrefix(v.Reason, "no_admin_token") {
		t.Errorf("not applicable: %+v", v)
	}
	v = e.ctl.Validate(bg, admin.ApplyRequest{Config: strings.Replace(e.configYAML(""), "air-gapped", "open-egress", 1)})
	if !v.Valid || v.Applicable || !strings.HasPrefix(v.Reason, "restart_required") {
		t.Errorf("restart: %+v", v)
	}
	v = e.ctl.Validate(bg, admin.ApplyRequest{Config: e.configYAML("limits: {max_inflight: -1}\n")})
	if v.Valid || v.Applicable || len(v.Errors) == 0 || v.Revision != "" {
		t.Errorf("invalid: %+v", v)
	}
	for _, msg := range v.Errors {
		if msg == "invalid configuration:" || strings.TrimSpace(msg) != msg || msg == "" {
			t.Errorf("an error message is just noise: %q in %v", msg, v.Errors)
		}
	}
	if !strings.Contains(strings.Join(v.Errors, "\n"), "max_inflight") {
		t.Errorf("the errors do not say what is wrong: %v", v.Errors)
	}
	v = e.ctl.Validate(bg, admin.ApplyRequest{Config: "bogus: [", Policies: nil})
	if v.Valid || len(v.Errors) == 0 {
		t.Errorf("not yaml: %+v", v)
	}
	if e.holder.Load() != running || e.count(`SELECT count(*) FROM admin_changes`) != records || e.count(`SELECT count(*) FROM config_revisions`) != 1 {
		t.Error("validating changed something")
	}
}

func TestAChangeThatCannotBeRecordedIsNotMade(t *testing.T) {
	e := newCtlEnv(t)
	running := e.holder.Load()
	if _, err := e.st.Pool().Exec(bg, `ALTER TABLE outbox RENAME TO outbox_gone`); err != nil {
		t.Fatal(err)
	}
	_, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("log: {level: debug}\n"), Base: running.Revision})
	if !errors.Is(err, admin.ErrAuditUnavailable) {
		t.Fatalf("err = %v, want ErrAuditUnavailable", err)
	}
	if e.holder.Load() != running || e.active().Revision != running.Revision {
		t.Error("the change was made although it could not be recorded")
	}
}

func TestSighupIsRecordedLikeAnAdminChange(t *testing.T) {
	e := newCtlEnv(t)
	e.write(e.configYAML("log: {level: debug}\n"))
	e.ctl.sighup(bg)
	e.write(e.configYAML("limits: {max_inflight: -1}\n"))
	e.ctl.sighup(bg)
	rows, err := e.st.Pool().Query(bg, `SELECT actor, action, outcome, target, (SELECT count(*) FROM outbox o WHERE o.event_id = c.event_id AND o.kind = 'admin_change')
		FROM admin_changes c WHERE actor = 'sighup' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type rec struct {
		actor, action, outcome, target string
		events                         int
	}
	var got []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.actor, &r.action, &r.outcome, &r.target, &r.events); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("records = %+v, want the reload and the refusal", got)
	}
	if want := (rec{"sighup", "config.reload", "applied", e.holder.Load().Revision, 1}); got[0] != want {
		t.Errorf("first = %+v, want %+v", got[0], want)
	}
	if got[1].action != "config.reload" || got[1].outcome != "rejected" || got[1].events != 1 {
		t.Errorf("second = %+v", got[1])
	}
}

func TestRestartFollowsTheFileWhenItChangedAndTheDatabaseWhenItDid(t *testing.T) {
	e := newCtlEnv(t)
	fileRev := e.holder.Load().Revision
	applied, err := e.ctl.Apply(bg, who("ops"), admin.ApplyRequest{Config: e.configYAML("log: {level: debug}\n"), Base: fileRev})
	if err != nil {
		t.Fatal(err)
	}
	restart := func() (*config.Snapshot, *config.Snapshot, error) {
		cfg, raw, err := config.Load(e.path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := config.Compile(cfg, raw, os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		holder := &config.Holder{}
		holder.Store(file)
		c := &controller{log: slog.New(slog.DiscardHandler), path: e.path, running: cfg, holder: holder, st: e.st}
		got, err := c.startupSnapshot(bg, file, raw)
		return file, got, err
	}

	// the file is the one it was: what the API applied survives the restart
	file, got, err := restart()
	if err != nil || got == file || got.Revision != applied.Revision {
		t.Fatalf("restart with an unchanged file: %v running %q, want %q", err, revOf(got), applied.Revision)
	}
	if e.active().Revision != applied.Revision {
		t.Error("resuming moved the pointer")
	}
	records := e.count(`SELECT count(*) FROM admin_changes`)

	// the operator edits the file: the file wins, and says so
	e.write(e.configYAML("log: {level: warn}\n"))
	file, got, err = restart()
	if err != nil || got != file {
		t.Fatalf("restart with an edited file: %v", err)
	}
	if a := e.active(); a.Revision != file.Revision || a.FileRevision != file.Revision || a.ActivatedBy != "startup" {
		t.Errorf("active = %+v", a)
	}
	var detail string
	if err := e.st.Pool().QueryRow(bg, `SELECT detail::text FROM admin_changes WHERE action = 'config.bootstrap' ORDER BY seq DESC LIMIT 1`).Scan(&detail); err != nil ||
		!strings.Contains(detail, "changed") || !strings.Contains(detail, applied.Revision) {
		t.Errorf("bootstrap record: %s (%v)", detail, err)
	}
	if e.count(`SELECT count(*) FROM admin_changes`) != records+1 {
		t.Error("the choice of the file was not recorded")
	}

	// starting again with that same file: nothing to decide, nothing recorded
	records = e.count(`SELECT count(*) FROM admin_changes`)
	if _, got, err = restart(); err != nil || got.Revision != file.Revision || e.count(`SELECT count(*) FROM admin_changes`) != records {
		t.Errorf("a plain restart: %v %q, records %d -> %d", err, revOf(got), records, e.count(`SELECT count(*) FROM admin_changes`))
	}
}

func revOf(s *config.Snapshot) string {
	if s == nil {
		return "<nil>"
	}
	return s.Revision
}

func TestRestartRefusesAnActiveRevisionThatCannotRunWithTheFile(t *testing.T) {
	e := newCtlEnv(t)
	base := e.holder.Load().Revision
	// something got into the database that the file's start cannot follow
	// (the file was edited back after an upgrade made a setting restart-only)
	bad := strings.Replace(e.configYAML(""), "air-gapped", "open-egress", 1)
	if _, err := e.st.Pool().Exec(bg, `INSERT INTO config_revisions (revision, profile, config_yaml, tavian_version) VALUES ('badbadbadbad', 'open-egress', $1, 'test')`, bad); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(bg, `UPDATE config_active SET revision = 'badbadbadbad'`); err != nil {
		t.Fatal(err)
	}
	cfg, raw, _ := config.Load(e.path)
	file, _ := config.Compile(cfg, raw, os.Getenv)
	holder := &config.Holder{}
	holder.Store(file)
	c := &controller{log: slog.New(slog.DiscardHandler), path: e.path, running: cfg, holder: holder, st: e.st}
	_, err := c.startupSnapshot(bg, file, raw)
	if err == nil || !strings.Contains(err.Error(), "badbadbadbad") || !strings.Contains(err.Error(), "profile") {
		t.Errorf("err = %v", err)
	}
	if e.active().Revision != "badbadbadbad" || base == "" {
		t.Error("a refused start moved the pointer")
	}
}

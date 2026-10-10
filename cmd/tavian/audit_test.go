package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/chain"
	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

func TestAuditKeygen(t *testing.T) {
	key := filepath.Join(t.TempDir(), "audit.key")
	var out, errOut bytes.Buffer
	if code := run([]string{"audit-keygen", "-out", key}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "public key: ed25519:") {
		t.Fatalf("output = %q", out.String())
	}
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	// refuses to overwrite, unless provisioning
	if code := run([]string{"audit-keygen", "-out", key}, &out, &errOut); code != 1 {
		t.Errorf("overwriting a key: exit %d", code)
	}
	out.Reset()
	if code := run([]string{"audit-keygen", "-out", key, "-if-missing"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "ed25519:") {
		t.Errorf("-if-missing: exit %d %q", code, out.String())
	}
	if code := run([]string{"audit-keygen"}, &out, &errOut); code != 2 {
		t.Errorf("without -out: exit %d", code)
	}
}

func TestVerifyAuditEndToEnd(t *testing.T) {
	st, url := storetest.New(t)
	t.Setenv("TAVIAN_AUDIT_TEST_DB", url)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	var out, errOut bytes.Buffer
	if code := run([]string{"audit-keygen", "-out", keyPath}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	pub := strings.TrimSpace(strings.TrimPrefix(strings.Split(out.String(), "\n")[0], "public key: "))
	cfgPath := filepath.Join(dir, "tavian.yaml")
	cfg := fmt.Sprintf(`
profile: air-gapped
database: { url_env: TAVIAN_AUDIT_TEST_DB, spool_dir: %s }
audit: { signing_key_file: audit.key, seal_every_events: 3 }
backends:
  - {id: local, type: openai, base_url: "http://127.0.0.1:8000/v1", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: local}]}
`, filepath.Join(dir, "spool"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// decision records, chained and sealed by the same consumer the gateway runs
	var rows []store.OutboxRow
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("d-%d", i)
		rows = append(rows, store.OutboxRow{EventID: id, Kind: "decision", OccurredAt: time.Now().UTC(), Payload: []byte(fmt.Sprintf(`{"decision_id":%q,"outcome":"served"}`, id))})
	}
	if err := st.InsertOutbox(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	signer, err := chain.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sealer := &chain.Sealer{Signer: signer, SealEveryEvents: 3}
	runner := &outbox.Runner{Pool: st.Pool(), Log: slog.New(slog.DiscardHandler)}
	runner.Add(sealer)
	if err := runner.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		runner.Step(context.Background(), sealer)
		var n int
		_ = st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_chain`).Scan(&n)
		if n == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not chained")
		}
		time.Sleep(5 * time.Millisecond)
	}

	seals := filepath.Join(dir, "seals.jsonl")
	out.Reset()
	errOut.Reset()
	code := run([]string{"verify-audit", "-config", cfgPath, "-public-key", pub, "-export-seals", seals}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "OK: no problem found") || !strings.Contains(out.String(), "signatures verified") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errOut.String())
	}
	if b, _ := os.ReadFile(seals); strings.Count(string(b), "\n") != 1 {
		t.Fatalf("exported seals:\n%s", b)
	}

	// the anchors still match
	out.Reset()
	if code := run([]string{"verify-audit", "-config", cfgPath, "-public-key", pub, "-anchors", seals}, &out, &errOut); code != 0 {
		t.Fatalf("anchors: exit %d\n%s", code, out.String())
	}

	// without the key the signatures are not checked, and it says so
	out.Reset()
	if code := run([]string{"verify-audit", "-config", cfgPath}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "signatures NOT verified") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}

	// someone edits a record
	if _, err := st.Pool().Exec(context.Background(), `UPDATE outbox SET payload = payload || '{"outcome":"refused"}' WHERE event_id = 'd-2'`); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"verify-audit", "-config", cfgPath, "-public-key", pub}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "FAILED") || !strings.Contains(out.String(), "entry 3") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}

	// bad arguments
	for _, args := range [][]string{
		{"verify-audit", "-config", cfgPath, "-public-key", "ed25519:nope"},
		{"verify-audit", "-config", cfgPath, "-anchors", filepath.Join(dir, "missing")},
	} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run([]string{"verify-audit", "-config", cfgPath, "-from-seal", "1"}, &out, &errOut); code != 1 {
		t.Errorf("-from-seal without a key: exit %d", code)
	}
}

// auditFixture is a database with a chain of decision records and one admin
// change, sealed, and a configuration file that reads the database through the
// environment variable TAVIAN_AUDIT_TEST_DB, to be pointed at any role.
type auditFixture struct {
	st      *store.Store
	url     string
	cfgPath string
	pub     string
	dir     string
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	st, url := storetest.New(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	var out, errOut bytes.Buffer
	if code := run([]string{"audit-keygen", "-out", keyPath}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	pub := strings.TrimSpace(strings.TrimPrefix(strings.Split(out.String(), "\n")[0], "public key: "))
	cfgPath := filepath.Join(dir, "tavian.yaml")
	// what an auditor needs: the profile, and where the database is
	if err := os.WriteFile(cfgPath, []byte("profile: air-gapped\ndatabase: { url_env: TAVIAN_AUDIT_TEST_DB }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rows []store.OutboxRow
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("d-%d", i)
		rows = append(rows, store.OutboxRow{EventID: id, Kind: "decision", OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Payload: []byte(fmt.Sprintf(`{"decision_id":%q,"outcome":"served"}`, id))})
	}
	if err := st.InsertOutbox(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAdminChange(context.Background(), store.AdminChange{
		EventID: "a-1", OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Actor: "ops-alice", Action: "config.apply", Target: "abc", Outcome: "applied",
	}); err != nil {
		t.Fatal(err)
	}
	signer, err := chain.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sealer := &chain.Sealer{Signer: signer, SealEveryEvents: 3}
	runner := &outbox.Runner{Pool: st.Pool(), Log: slog.New(slog.DiscardHandler)}
	runner.Add(sealer)
	if err := runner.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		runner.Step(context.Background(), sealer)
		var n int
		_ = st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_chain`).Scan(&n)
		if n == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not chained")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return &auditFixture{st: st, url: url, cfgPath: cfgPath, pub: pub, dir: dir}
}

func TestAuditRolePrintsTheScriptAndRunsNothing(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"audit-role"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `CREATE ROLE "tavian_auditor" LOGIN NOSUPERUSER`) || !strings.Contains(out.String(), `GRANT SELECT ON`) ||
		!strings.Contains(out.String(), `"public"."audit_chain"`) || !strings.Contains(errOut.String(), "Nothing was run") {
		t.Errorf("stdout:\n%s\nstderr: %s", out.String(), errOut.String())
	}
	out.Reset()
	if code := run([]string{"audit-role", "-name", "bob", "-database", "prod", "-schema", "tavian"}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), `CREATE ROLE "bob"`) || !strings.Contains(out.String(), `ON DATABASE "prod"`) || !strings.Contains(out.String(), `"tavian"."outbox"`) {
		t.Errorf("custom names: %d\n%s", code, out.String())
	}
	for _, args := range [][]string{{"audit-role", "-name", `x"; DROP TABLE outbox; --`}, {"audit-role", "-name", ""}, {"audit-role", "-bogus"}} {
		out.Reset()
		if code := run(args, &out, &errOut); code != 2 || out.Len() != 0 {
			t.Errorf("%v: exit %d, output %q", args, code, out.String())
		}
	}
}

func TestAnAuditorWithTheReadOnlyRoleVerifiesAndExports(t *testing.T) {
	f := newAuditFixture(t)
	t.Setenv("TAVIAN_AUDIT_TEST_DB", storetest.AuditorURL(t, f.url))
	var out, errOut bytes.Buffer
	seals := filepath.Join(f.dir, "seals.jsonl")
	if code := run([]string{"verify-audit", "-config", f.cfgPath, "-public-key", f.pub, "-export-seals", seals}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "OK: no problem found") || !strings.Contains(out.String(), "signatures verified") || !strings.Contains(out.String(), "7 entries") {
		t.Fatalf("verify-audit as the auditor: exit %d\n%s%s", code, out.String(), errOut.String())
	}

	// export to a file: the entries, with their records
	file := filepath.Join(f.dir, "export.jsonl")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"audit-export", "-config", f.cfgPath, "-o", file}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "exported 7 entries") || out.Len() != 0 {
		t.Fatalf("audit-export: exit %d\nstdout %q\nstderr %s", code, out.String(), errOut.String())
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("export file: %v %v", info, err)
	}
	b, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 7 {
		t.Fatalf("%d lines:\n%s", len(lines), b)
	}
	var last chain.Entry
	if err := json.Unmarshal([]byte(lines[6]), &last); err != nil || last.Position != 7 || last.Kind != "admin_change" || last.EventID != "a-1" || last.EntryHash == "" ||
		!strings.Contains(string(last.Record), `"actor":"ops-alice"`) {
		t.Errorf("last line = %s (%v)", lines[6], err)
	}
	// an existing file is never written over by accident
	out.Reset()
	if code := run([]string{"audit-export", "-config", f.cfgPath, "-o", file}, &out, &errOut); code != 1 {
		t.Errorf("over an existing file: exit %d", code)
	}
	if code := run([]string{"audit-export", "-config", f.cfgPath, "-o", file, "-force", "-kind", "admin_change"}, &out, &errOut); code != 0 {
		t.Errorf("-force: exit %d", code)
	}
	if b, _ := os.ReadFile(file); strings.Count(string(b), "\n") != 1 || !strings.Contains(string(b), `"kind":"admin_change"`) {
		t.Errorf("-kind admin_change:\n%s", b)
	}
	// to the standard output, with filters
	out.Reset()
	if code := run([]string{"audit-export", "-config", f.cfgPath, "-kind", "decision", "-from-position", "4", "-since", "2020-01-01", "-until", "2999-01-01"}, &out, &errOut); code != 0 ||
		strings.Count(out.String(), "\n") != 2 {
		t.Errorf("filters: exit %d\n%s", code, out.String())
	}

	// bad arguments
	for _, args := range [][]string{
		{"audit-export", "-config", f.cfgPath, "-kind", "usage"},
		{"audit-export", "-config", f.cfgPath, "-since", "yesterday"},
		{"audit-export", "-config", f.cfgPath, "-until", "2026-13-45"},
		{"audit-export", "-bogus"},
	} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run([]string{"audit-export", "-config", filepath.Join(f.dir, "missing.yaml")}, &out, &errOut); code != 1 {
		t.Errorf("missing config: exit %d", code)
	}

	// someone with the right to write edits a record: the auditor finds it, and cannot undo it
	if _, err := f.st.Pool().Exec(context.Background(), `UPDATE outbox SET payload = payload || '{"outcome":"refused"}' WHERE event_id = 'd-2'`); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"verify-audit", "-config", f.cfgPath, "-public-key", f.pub}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "FAILED") {
		t.Errorf("tampering: exit %d\n%s", code, out.String())
	}
}

func TestAuditExportNeedsADatabase(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tavian.yaml")
	if err := os.WriteFile(cfg, []byte("profile: air-gapped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"audit-export", "-config", cfg}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "database.url_env") {
		t.Errorf("exit %d: %s", code, errOut.String())
	}
}

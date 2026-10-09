package main

import (
	"bytes"
	"context"
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

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/config"
)

func TestKeygenAndValidate(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"keygen"}, &out, &errOut); code != 0 {
		t.Fatalf("keygen exit = %d", code)
	}
	var hash string
	for _, l := range strings.Split(out.String(), "\n") {
		if h, ok := strings.CutPrefix(l, "hash: "); ok {
			hash = h
		}
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("keygen output = %q", out.String())
	}

	cfg := `
profile: air-gapped
backends:
  - {id: local, type: openai, base_url: "http://127.0.0.1:8000/v1", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: local}]}
api_keys:
  - {id: dev, hash: "` + hash + `", team: t, application: a, allowed_models: ["*"]}
`
	path := filepath.Join(t.TempDir(), "tavian.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"validate", "-config", path}, &out, &errOut); code != 0 {
		t.Fatalf("validate exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "profile=air-gapped") {
		t.Errorf("validate output = %q", out.String())
	}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("profile: air-gapped\nunknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "-config", path}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "unknown_field") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 {
		t.Errorf("no args exit = %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Errorf("unknown command exit = %d", code)
	}
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "tavian") {
		t.Errorf("version exit = %d out = %q", code, out.String())
	}
}

func TestReloadKeepsCurrentRevisionOnRejection(t *testing.T) {
	_, hash, _ := auth.GenerateKey()
	write := func(extra string) string {
		path := filepath.Join(t.TempDir(), "tavian.yaml")
		body := `profile: air-gapped
` + extra + `backends:
  - {id: local, type: openai, base_url: "http://127.0.0.1:9/v1", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: local}]}
api_keys:
  - {id: dev, hash: "` + hash + `", team: t, application: a, allowed_models: ["*"]}
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	log := slog.New(slog.DiscardHandler)
	first := write("")
	cfg, raw, err := config.Load(first)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	holder := &config.Holder{}
	holder.Store(snap)

	// Changing the database section needs a restart: the revision must not move.
	t.Setenv("TAVIAN_RELOAD_TEST_DB", "postgres://x")
	reload(context.Background(), log, write("database:\n  url_env: TAVIAN_RELOAD_TEST_DB\n"), cfg, holder, nil, nil)
	if holder.Load() != snap {
		t.Error("reload with a changed database section was applied")
	}

	// An unrelated, valid change is applied.
	reload(context.Background(), log, write("log: {level: debug}\n"), cfg, holder, nil, nil)
	if holder.Load() == snap {
		t.Error("valid reload was not applied")
	}
}

func TestSameOIDCConnectionIgnoresOnlyMappings(t *testing.T) {
	base := config.OIDCConfig{Issuer: "https://idp/r", Audience: "a", Algorithms: []string{"RS256"}}
	withMappings := base
	withMappings.Mappings = []config.OIDCMapping{{Group: "g", Team: "t", AllowedModels: []string{"*"}}}
	if !sameOIDCConnection(base, withMappings) {
		t.Error("changing mappings must be allowed on reload")
	}
	for name, mut := range map[string]func(*config.OIDCConfig){
		"issuer":     func(c *config.OIDCConfig) { c.Issuer = "https://other/r" },
		"audience":   func(c *config.OIDCConfig) { c.Audience = "b" },
		"algorithms": func(c *config.OIDCConfig) { c.Algorithms = []string{"RS256", "ES256"} },
		"claims":     func(c *config.OIDCConfig) { c.Claims.Groups = "roles" },
	} {
		changed := base
		mut(&changed)
		if sameOIDCConnection(base, changed) {
			t.Errorf("a change of %s must require a restart", name)
		}
	}
}

func TestLogKeyExpiriesNamesKeysButNotTheirSecrets(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := &config.Snapshot{Keys: map[string]*config.APIKey{
		"hash-of-gone": {ID: "gone", ExpiresAt: now.Add(-time.Hour)},
		"hash-of-soon": {ID: "soon", ExpiresAt: now.Add(24 * time.Hour)},
		"hash-of-far":  {ID: "far", ExpiresAt: now.Add(365 * 24 * time.Hour)},
		"hash-of-none": {ID: "none"},
	}}
	var buf bytes.Buffer
	logKeyExpiries(slog.New(slog.NewTextHandler(&buf, nil)), snap, now)
	out := buf.String()
	for _, want := range []string{"refused", "gone", "expire within 14 days", "soon"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"far", "none", "hash-of"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("log mentions %q:\n%s", unwanted, out)
		}
	}
	buf.Reset()
	logKeyExpiries(slog.New(slog.NewTextHandler(&buf, nil)), &config.Snapshot{}, now)
	if buf.Len() != 0 {
		t.Errorf("nothing to say, got %q", buf.String())
	}
}

func TestValidateReportsPolicyProblemsAndWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "tavian.yaml")
	write := func(policy string) {
		t.Helper()
		_ = os.WriteFile(filepath.Join(dir, "policies", "p.yaml"), []byte(policy), 0o600)
		_ = os.WriteFile(cfg, []byte(`
profile: air-gapped
policy: { dir: policies }
backends:
  - {id: local, type: openai, base_url: "http://127.0.0.1:8000/v1", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: local}]}
api_keys:
  - {id: dev, hash: "sha256:`+strings.Repeat("a", 64)+`", team: t, application: a, allowed_models: ["*"]}
`), 0o600)
	}
	const head = "apiVersion: tavian/v1alpha1\nkind: Policy\nmetadata: { name: p }\nspec:\n  scope: { team: t }\n"

	write(head + "  destinations: { confidential: [internal, approved-external] }\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "-config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "policies=2") || !strings.Contains(errOut.String(), "warning: policy p: destinations.confidential lists approved-external") {
		t.Errorf("stdout %q stderr %q", out.String(), errOut.String())
	}

	write(head + "  classification:\n    infer:\n      - { id: r, when: 'finding.subtyp == \"x\"', label: restricted }\n")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"validate", "-config", cfg}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "p.yaml") || !strings.Contains(errOut.String(), "check the field names") {
		t.Errorf("exit = %d, stderr %q", code, errOut.String())
	}
}

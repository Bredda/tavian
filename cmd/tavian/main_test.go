package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	reload(context.Background(), log, write("database:\n  url_env: TAVIAN_RELOAD_TEST_DB\n"), cfg, holder, nil)
	if holder.Load() != snap {
		t.Error("reload with a changed database section was applied")
	}

	// An unrelated, valid change is applied.
	reload(context.Background(), log, write("log: {level: debug}\n"), cfg, holder, nil)
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

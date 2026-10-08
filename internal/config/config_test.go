package config

import (
	"strings"
	"testing"
)

const validYAML = `
profile: controlled-egress
backends:
  - id: local
    type: openai
    base_url: http://vllm.internal:8000/v1
    destination_class: internal
  - id: azure-eu
    type: openai
    base_url: https://eu.example.com/openai/v1
    destination_class: approved-external
    api_key_env: AZURE_KEY
models:
  - name: llama-70b
    type: chat
    route:
      - backend: local
        upstream_model: meta-llama/Llama-3.3-70B-Instruct
  - name: gpt-eu
    type: chat
    route:
      - backend: azure-eu
api_keys:
  - id: dev
    hash: sha256:0000000000000000000000000000000000000000000000000000000000000001
    team: research
    application: demo
    allowed_models: ["*"]
`

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func compile(t *testing.T, yaml string, e map[string]string) (*Snapshot, error) {
	t.Helper()
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return Compile(cfg, []byte(yaml), env(e))
}

func TestCompileValid(t *testing.T) {
	s, err := compile(t, validYAML, map[string]string{"AZURE_KEY": "secret"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(s.Revision) != 12 {
		t.Errorf("revision = %q", s.Revision)
	}
	if got := s.Endpoints["vllm.internal:8000"]; got != ClassInternal {
		t.Errorf("internal endpoint class = %q", got)
	}
	if got := s.Endpoints["eu.example.com:443"]; got != ClassApprovedExternal {
		t.Errorf("default https port/class = %q", got)
	}
	if s.Backends["azure-eu"].Credential != "secret" {
		t.Error("credential not resolved from env")
	}
	if s.Backends["local"].MaxClassification != LabelRestricted {
		t.Errorf("default max classification (internal) = %q", s.Backends["local"].MaxClassification)
	}
	if s.Backends["azure-eu"].MaxClassification != LabelInternal {
		t.Errorf("default max classification (approved-external) = %q", s.Backends["azure-eu"].MaxClassification)
	}
	if got := s.Models["gpt-eu"].Route[0].UpstreamModel; got != "gpt-eu" {
		t.Errorf("upstream model default = %q", got)
	}
	if strings.Join(s.ModelNames, ",") != "gpt-eu,llama-70b" {
		t.Errorf("ModelNames = %v", s.ModelNames)
	}
	if _, ok := s.Keys["0000000000000000000000000000000000000000000000000000000000000001"]; !ok {
		t.Error("key not indexed by hash")
	}
}

func TestRevisionDependsOnContent(t *testing.T) {
	a, _ := compile(t, validYAML, map[string]string{"AZURE_KEY": "x"})
	b, _ := compile(t, validYAML+"\n# comment\n", map[string]string{"AZURE_KEY": "x"})
	if a.Revision == b.Revision {
		t.Error("revision must change when the file changes")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte("profile: air-gapped\nprofil: oops\n")); err == nil {
		t.Fatal("expected error for unknown field")
	}
	if _, err := Parse([]byte("")); err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		env  map[string]string
		want string
	}{
		{"missing profile", "backends: []\n", nil, "profile: required"},
		{"unknown profile", "profile: wide-open\n", nil, "unknown value"},
		{"profile forbids class", `
profile: air-gapped
backends:
  - {id: ext, type: openai, base_url: "https://x.example.com", destination_class: approved-external}
`, nil, "not allowed by profile"},
		{"controlled forbids public", `
profile: controlled-egress
backends:
  - {id: pub, type: openai, base_url: "https://x.example.com", destination_class: public-external}
`, nil, "not allowed by profile"},
		{"bad class", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "http://x", destination_class: cloud}
`, nil, "destination_class must be"},
		{"duplicate backend", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "http://x", destination_class: internal}
  - {id: b, type: openai, base_url: "http://y", destination_class: internal}
`, nil, "duplicate id"},
		{"relative url", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "/v1", destination_class: internal}
`, nil, "not a valid absolute URL"},
		{"url with credentials", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "http://u:p@x/v1", destination_class: internal}
`, nil, "must not contain credentials"},
		{"scheme", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "ftp://x", destination_class: internal}
`, nil, "scheme must be http or https"},
		{"unsupported type", `
profile: open-egress
backends:
  - {id: b, type: bedrock, base_url: "http://x", destination_class: internal}
`, nil, "unsupported type"},
		{"endpoint class conflict", `
profile: open-egress
backends:
  - {id: a, type: openai, base_url: "http://x:80/v1", destination_class: internal}
  - {id: b, type: openai, base_url: "http://x/v2", destination_class: public-external}
`, nil, "already declared"},
		{"missing credential env", `
profile: open-egress
backends:
  - {id: b, type: openai, base_url: "http://x", destination_class: internal, api_key_env: NOPE}
`, nil, "NOPE"},
		{"unknown backend in route", `
profile: open-egress
models:
  - {name: m, type: chat, route: [{backend: ghost}]}
`, nil, "unknown backend"},
		{"empty route", `
profile: open-egress
models:
  - {name: m, type: chat, route: []}
`, nil, "route must list"},
		{"model type", `
profile: open-egress
models:
  - {name: m, type: embedding, route: []}
`, nil, "unsupported type"},
		{"bad key hash", `
profile: open-egress
api_keys:
  - {id: k, hash: "plaintext", allowed_models: ["*"]}
`, nil, "sha256:"},
		{"empty allowed models", `
profile: open-egress
api_keys:
  - {id: k, hash: "sha256:0000000000000000000000000000000000000000000000000000000000000002"}
`, nil, "allowed_models"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compile(t, tc.yaml, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestCompileReportsAllProblems(t *testing.T) {
	_, err := compile(t, `
profile: air-gapped
backends:
  - {id: a, type: nope, base_url: "http://x", destination_class: internal}
models:
  - {name: m, type: chat, route: [{backend: ghost}]}
`, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"unsupported type", "unknown backend"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestHolder(t *testing.T) {
	var h Holder
	if h.Load() != nil {
		t.Fatal("empty holder must return nil")
	}
	s := &Snapshot{Revision: "abc"}
	h.Store(s)
	if h.Load() != s {
		t.Fatal("Load must return the stored snapshot")
	}
}

func TestDatabaseSectionValidation(t *testing.T) {
	base := "profile: air-gapped\n"
	cfg, err := Parse([]byte(base + "database:\n  url_env: TAVIAN_TEST_DB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.SpoolDir == "" || cfg.Database.SpoolMaxBytes == 0 || cfg.Database.EmitTimeout == 0 {
		t.Errorf("defaults not applied: %+v", cfg.Database)
	}
	if _, err := Compile(cfg, nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "TAVIAN_TEST_DB") {
		t.Errorf("unset url_env variable not reported: %v", err)
	}
	if _, err := Compile(cfg, nil, func(string) string { return "postgres://x" }); err != nil {
		t.Errorf("valid database config rejected: %v", err)
	}

	small, _ := Parse([]byte(base + "database:\n  spool_max_bytes: 100\n"))
	if _, err := Compile(small, nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "spool_max_bytes") {
		t.Errorf("tiny spool accepted: %v", err)
	}
}

func oidcYAML(extra string) string {
	return `profile: air-gapped
oidc:
  issuer: http://keycloak.internal:8080/realms/tavian
  audience: tavian
  destination_class: internal
` + extra
}

func compileOIDCYAML(t *testing.T, y string) (*Snapshot, error) {
	t.Helper()
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return Compile(cfg, []byte(y), func(string) string { return "" })
}

func TestOIDCCompiles(t *testing.T) {
	s, err := compileOIDCYAML(t, oidcYAML(`  jwks_uri: http://keys.internal:9000/certs
  claims: {groups: realm_access.roles}
  mappings:
    - {group: ai-research, team: research, allowed_models: ["llama-*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	// With an explicit jwks_uri the issuer is only an identifier: no discovery,
	// so only the keys' host is opened to the egress guard.
	if s.Endpoints["keys.internal:9000"] != ClassInternal || len(s.Endpoints) != 1 {
		t.Errorf("egress allow-list = %v", s.Endpoints)
	}
	d, err := compileOIDCYAML(t, oidcYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	if d.Endpoints["keycloak.internal:8080"] != ClassInternal {
		t.Errorf("discovery needs the issuer on the allow-list: %v", d.Endpoints)
	}
	o := s.OIDC
	if o.Claims.Groups != "realm_access.roles" || o.Claims.Application != "azp" || o.ClockSkew == 0 ||
		o.JWKSRefresh == 0 || o.JWKSMaxStaleness < o.JWKSRefresh || len(o.Algorithms) == 0 || len(o.Mappings) != 1 {
		t.Errorf("settings / defaults = %+v", o)
	}
}

func TestOIDCOffByDefault(t *testing.T) {
	s, err := compileOIDCYAML(t, "profile: air-gapped\n")
	if err != nil || s.OIDC.Issuer != "" {
		t.Errorf("err=%v issuer=%q", err, s.OIDC.Issuer)
	}
}

func TestOIDCValidation(t *testing.T) {
	base := "profile: air-gapped\noidc:\n"
	for name, tc := range map[string]struct{ yaml, want string }{
		"audience required": {
			base + "  issuer: http://k.internal/r\n  destination_class: internal\n", "audience"},
		"class required": {
			base + "  issuer: http://k.internal/r\n  audience: a\n", "destination_class"},
		"settings without issuer": {
			base + "  audience: a\n", "issuer is required"},
		"profile forbids the class": {
			"profile: air-gapped\noidc:\n  issuer: https://login.example/r\n  audience: a\n  destination_class: approved-external\n", "not allowed by profile"},
		"plain http only for internal": {
			"profile: controlled-egress\noidc:\n  issuer: http://login.example/r\n  audience: a\n  destination_class: approved-external\n", "https"},
		"symmetric algorithms refused": {
			oidcYAML("  algorithms: [HS256]\n"), "HS256"},
		"staleness shorter than refresh": {
			oidcYAML("  jwks_refresh: 1h\n  jwks_max_staleness: 10m\n"), "jwks_max_staleness"},
		"mapping without models": {
			oidcYAML("  mappings:\n    - {group: g, team: t}\n"), "allowed_models"},
		"mapping with a bad team": {
			oidcYAML("  mappings:\n    - {group: g, team: 'Not A Slug', allowed_models: [m]}\n"), "team"},
		"group mapped twice": {
			oidcYAML("  mappings:\n    - {group: g, team: a, allowed_models: [m]}\n    - {group: g, team: b, allowed_models: [m]}\n"), "twice"},
		"jwks uri with credentials": {
			oidcYAML("  jwks_uri: http://u:p@k.internal/certs\n"), "credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := compileOIDCYAML(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestOIDCEndpointCannotChangeClassOfABackend(t *testing.T) {
	y := `profile: controlled-egress
oidc:
  issuer: https://login.example/r
  audience: a
  destination_class: approved-external
backends:
  - {id: b, type: openai, base_url: "https://login.example/v1", destination_class: internal}
`
	if _, err := compileOIDCYAML(t, y); err == nil || !strings.Contains(err.Error(), "already declared") {
		t.Errorf("err = %v", err)
	}
}

func TestMaxInflight(t *testing.T) {
	cfg, err := Parse([]byte("profile: air-gapped\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxInflight != 256 {
		t.Errorf("default max_inflight = %d", cfg.Limits.MaxInflight)
	}
	bad, _ := Parse([]byte("profile: air-gapped\nlimits: {max_inflight: -1}\n"))
	if _, err := Compile(bad, nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "max_inflight") {
		t.Errorf("negative max_inflight accepted: %v", err)
	}
}

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestQuotaDefaults(t *testing.T) {
	cfg, err := Parse([]byte("profile: air-gapped\n"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := Compile(cfg, nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if snap.Quota.DefaultOutputTokens != 1024 {
		t.Errorf("default_output_tokens = %d, want 1024", snap.Quota.DefaultOutputTokens)
	}
	set, _ := Parse([]byte("profile: air-gapped\nquota: {default_output_tokens: 300}\n"))
	if snap, err := Compile(set, nil, func(string) string { return "" }); err != nil || snap.Quota.DefaultOutputTokens != 300 {
		t.Errorf("explicit value: %v %+v", err, snap)
	}
	for _, bad := range []string{"-1", "2000000"} {
		cfg, _ := Parse([]byte("profile: air-gapped\nquota: {default_output_tokens: " + bad + "}\n"))
		if _, err := Compile(cfg, nil, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "default_output_tokens") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
	if _, err := Parse([]byte("profile: air-gapped\nquota: {default_output: 1}\n")); err == nil {
		t.Error("a typo in quota was accepted")
	}
}

func compileKeys(t *testing.T, keysYAML string) (*Snapshot, error) {
	t.Helper()
	y := "profile: air-gapped\napi_keys:\n" + keysYAML
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return Compile(cfg, []byte(y), func(string) string { return "" })
}

const hashA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const hashB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestKeyExpiryAndClearanceParsing(t *testing.T) {
	s, err := compileKeys(t, `  - {id: dated, hash: `+hashA+`, allowed_models: ["*"], expires_at: 2027-03-01}
  - {id: precise, hash: `+hashB+`, allowed_models: ["*"], expires_at: "2027-03-01T10:00:00+02:00", max_classification: confidential}
`)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*APIKey{}
	for _, k := range s.Keys {
		byID[k.ID] = k
	}
	if want := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC); !byID["dated"].ExpiresAt.Equal(want) {
		t.Errorf("a plain date means 00:00 UTC, got %v", byID["dated"].ExpiresAt)
	}
	if want := time.Date(2027, 3, 1, 8, 0, 0, 0, time.UTC); !byID["precise"].ExpiresAt.Equal(want) {
		t.Errorf("RFC 3339 offset not honoured: %v", byID["precise"].ExpiresAt)
	}
	if byID["dated"].MaxClassification != LabelInternal || byID["precise"].MaxClassification != LabelConfidential {
		t.Errorf("clearances: %q / %q", byID["dated"].MaxClassification, byID["precise"].MaxClassification)
	}
	if _, err := compileKeys(t, `  - {id: bad, hash: `+hashA+`, allowed_models: ["*"], max_classification: top-secret}
`); err == nil || !strings.Contains(err.Error(), "max_classification") {
		t.Errorf("unknown clearance accepted: %v", err)
	}
	cfg, err := Parse([]byte("profile: air-gapped\napi_keys:\n  - {id: bad, hash: x, expires_at: not-a-date}\n"))
	if err == nil {
		t.Errorf("a malformed expires_at must be a parse error, got %+v", cfg.APIKeys)
	}
}

func TestExpiredKeysDoNotPreventStartup(t *testing.T) {
	// A key that expired while the file stayed as it was must not take the
	// gateway down on restart: it is refused at request time and named in the logs.
	if _, err := compileKeys(t, `  - {id: old, hash: `+hashA+`, allowed_models: ["*"], expires_at: 2001-01-01}
`); err != nil {
		t.Errorf("an expired key made the configuration invalid: %v", err)
	}
}

func TestOIDCMappingClearance(t *testing.T) {
	y := oidcYAML(`  mappings:
    - {group: a, team: t, allowed_models: [m]}
    - {group: b, team: t, allowed_models: [m], max_classification: restricted}
`)
	s, err := compileOIDCYAML(t, y)
	if err != nil {
		t.Fatal(err)
	}
	if got := []Classification{s.OIDC.Mappings[0].MaxClassification, s.OIDC.Mappings[1].MaxClassification}; got[0] != LabelInternal || got[1] != LabelRestricted {
		t.Errorf("clearances = %v", got)
	}
	bad := oidcYAML("  mappings:\n    - {group: a, team: t, allowed_models: [m], max_classification: nope}\n")
	if _, err := compileOIDCYAML(t, bad); err == nil || !strings.Contains(err.Error(), "max_classification") {
		t.Errorf("unknown clearance accepted: %v", err)
	}
}

func TestKeyExpiries(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Snapshot{Keys: map[string]*APIKey{
		"1": {ID: "never"},
		"2": {ID: "gone", ExpiresAt: now.Add(-time.Hour)},
		"3": {ID: "at-the-instant", ExpiresAt: now},
		"4": {ID: "soon", ExpiresAt: now.Add(48 * time.Hour)},
		"5": {ID: "later", ExpiresAt: now.Add(90 * 24 * time.Hour)},
	}}
	e := s.KeyExpiries(now, 14*24*time.Hour)
	if strings.Join(e.Expired, ",") != "at-the-instant,gone" || strings.Join(e.Soon, ",") != "soon" {
		t.Errorf("expired %v soon %v", e.Expired, e.Soon)
	}
	if !e.HasNext || e.Next != 48*time.Hour {
		t.Errorf("next = %v (%v)", e.Next, e.HasNext)
	}
	if none := (&Snapshot{Keys: map[string]*APIKey{"1": {ID: "never"}}}).KeyExpiries(now, time.Hour); none.HasNext || len(none.Expired) != 0 {
		t.Errorf("no expiring key: %+v", none)
	}
}

func TestInspectionSection(t *testing.T) {
	azure := map[string]string{"AZURE_KEY": "k"}
	// On by default, with a per-process fingerprint key.
	s, err := compile(t, validYAML, azure)
	if err != nil {
		t.Fatal(err)
	}
	if s.Inspector == nil || !s.Inspector.Enabled() || !s.Inspector.EphemeralKey() || len(s.Inspector.Detectors()) == 0 {
		t.Errorf("default inspector = %+v", s.Inspector)
	}

	s, err = compile(t, validYAML+"inspection:\n  budget: 20ms\n  fingerprint_key_env: FP_KEY\n", map[string]string{"AZURE_KEY": "k", "FP_KEY": "a-long-enough-secret-key"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Inspector.EphemeralKey() {
		t.Error("a configured key must be used")
	}

	s, err = compile(t, validYAML+"inspection:\n  enabled: false\n", azure)
	if err != nil || s.Inspector.Enabled() {
		t.Errorf("inspection can be turned off explicitly: err = %v", err)
	}

	for name, section := range map[string]string{
		"key variable unset": "inspection:\n  fingerprint_key_env: NOPE\n",
		"budget too small":   "inspection:\n  budget: 1us\n",
		"budget too large":   "inspection:\n  budget: 5m\n",
	} {
		if _, err := compile(t, validYAML+section, azure); err == nil || !strings.Contains(err.Error(), "inspection:") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Parse([]byte(validYAML + "inspection:\n  enabeld: false\n")); err == nil {
		t.Error("a typo in the inspection section must be rejected")
	}
}

func TestInspectionDetectorsFromConfig(t *testing.T) {
	azure := map[string]string{"AZURE_KEY": "k"}
	s, err := compile(t, validYAML+`
inspection:
  disable: [pii.phone]
  dictionaries:
    - name: codenames
      severity: high
      terms: ["Projet Aurore", "Falcon"]
    - name: markings
      terms: ["DIFFUSION RESTREINTE"]
      whole_word: false
  patterns:
    - name: contract
      regex: 'CTR-\d{6}'
`, azure)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range s.Inspector.Detectors() {
		names[d.Name] = true
	}
	for _, want := range []string{"pii.iban", "custom.codenames", "custom.markings", "custom.contract"} {
		if !names[want] {
			t.Errorf("detector %s missing from %v", want, names)
		}
	}
	if names["pii.phone"] {
		t.Error("pii.phone should be disabled")
	}

	for name, section := range map[string]string{
		"unknown detector": "inspection:\n  disable: [pii.nope]\n",
		"bad regex":        "inspection:\n  patterns:\n    - {name: p, regex: '('}\n",
		"no terms":         "inspection:\n  dictionaries:\n    - {name: d}\n",
		"unknown field":    "inspection:\n  dictionaries:\n    - {name: d, terms: [abc], word: true}\n",
	} {
		cfg, perr := Parse([]byte(validYAML + section))
		if perr != nil {
			continue // rejected at parse time: also fine
		}
		if _, err := Compile(cfg, []byte(validYAML+section), env(azure)); err == nil || !strings.Contains(err.Error(), "inspection:") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

const teamPolicy = `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: research-limits }
spec:
  scope: { team: research }
  models: { deny: ["*-preview"] }
`

func writeConfigWithPolicies(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, "policies", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "tavian.yaml")
	if err := os.WriteFile(path, []byte(validYAML+"policy:\n  dir: policies\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolicyDirIsLoadedRelativeToTheConfigFile(t *testing.T) {
	path := writeConfigWithPolicies(t, map[string]string{
		"research.yaml": teamPolicy,
		"README.txt":    "not a policy",
		".hidden.yaml":  "this would not parse: [",
		"second.yml":    strings.ReplaceAll(strings.ReplaceAll(teamPolicy, "research-limits", "other"), "team: research", "team: finance"),
	})
	t.Chdir(t.TempDir()) // the working directory must not matter
	cfg, raw, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PolicySources) != 2 {
		t.Fatalf("sources = %d, want the two YAML files only", len(cfg.PolicySources))
	}
	snap, err := Compile(cfg, raw, env(map[string]string{"AZURE_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(snap.Policy.Names(), ","); got != "baseline,research-limits,other" {
		t.Errorf("policies = %s", got)
	}
	if len(snap.PolicySources) != 2 {
		t.Errorf("snapshot keeps %d sources", len(snap.PolicySources))
	}
}

func TestRevisionCoversThePolicyFiles(t *testing.T) {
	load := func(files map[string]string) string {
		cfg, raw, err := Load(writeConfigWithPolicies(t, files))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Compile(cfg, raw, env(map[string]string{"AZURE_KEY": "k"}))
		if err != nil {
			t.Fatal(err)
		}
		return s.Revision
	}
	a := load(map[string]string{"a.yaml": teamPolicy})
	if a != load(map[string]string{"a.yaml": teamPolicy}) {
		t.Error("the revision must be stable")
	}
	if a == load(map[string]string{"a.yaml": strings.ReplaceAll(teamPolicy, "-preview", "-beta")}) {
		t.Error("changing a rule must change the revision")
	}
	if a == load(map[string]string{"b.yaml": teamPolicy}) {
		t.Error("renaming a file must change the revision")
	}
	if a == load(nil) {
		t.Error("removing the policies must change the revision")
	}
}

// Without policy files the revision is what it was before they existed, so
// that upgrading does not make every deployment look reconfigured.
func TestRevisionWithoutPoliciesIsTheHashOfTheFile(t *testing.T) {
	s, err := compile(t, validYAML, map[string]string{"AZURE_KEY": "k"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(validYAML))
	if want := hex.EncodeToString(sum[:])[:12]; s.Revision != want {
		t.Errorf("revision = %s, want %s", s.Revision, want)
	}
	if len(s.Policy.Names()) != 1 || s.Policy.Names()[0] != "baseline" {
		t.Errorf("policies = %v, want the baseline only", s.Policy.Names())
	}
}

func TestInvalidPoliciesRejectTheConfiguration(t *testing.T) {
	path := writeConfigWithPolicies(t, map[string]string{
		"bad.yaml": "apiVersion: tavian/v1alpha1\nkind: Policy\nmetadata: { name: bad }\nspec: { scope: { organization: true }, audit: { content: hash } }\n",
	})
	cfg, raw, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(cfg, raw, env(map[string]string{"AZURE_KEY": "k"})); err == nil || !strings.Contains(err.Error(), "bad.yaml") || !strings.Contains(err.Error(), "audit") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("a missing configuration file must fail")
	}
	missing := filepath.Join(t.TempDir(), "tavian.yaml")
	_ = os.WriteFile(missing, []byte(validYAML+"policy:\n  dir: not-there\n"), 0o600)
	if _, _, err := Load(missing); err == nil || !strings.Contains(err.Error(), "policy.dir") {
		t.Errorf("missing policy dir: %v", err)
	}
}

// Package config loads, validates and compiles Tavian's configuration into an
// immutable Snapshot (ADR-0003). The data plane only ever reads Snapshots; it
// never touches the configuration file or the database on the request path.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Profile is the deployment profile (ARCHITECTURE.md §2, ADR-0008).
type Profile string

const (
	ProfileAirGapped        Profile = "air-gapped"
	ProfileControlledEgress Profile = "controlled-egress"
	ProfileOpenEgress       Profile = "open-egress"
)

// allows reports whether backends of class c may exist under profile p.
func (p Profile) allows(c DestinationClass) bool {
	switch p {
	case ProfileAirGapped:
		return c == ClassInternal
	case ProfileControlledEgress:
		return c == ClassInternal || c == ClassApprovedExternal
	case ProfileOpenEgress:
		return c == ClassInternal || c == ClassApprovedExternal || c == ClassPublicExternal
	}
	return false
}

// DestinationClass says where a backend runs, from a data-governance viewpoint.
type DestinationClass string

const (
	ClassInternal         DestinationClass = "internal"
	ClassApprovedExternal DestinationClass = "approved-external"
	ClassPublicExternal   DestinationClass = "public-external"
)

// Classification is a data sensitivity label. The default scheme is ordered
// public < internal < confidential < restricted (DOMAIN_MODEL.md).
type Classification string

const (
	LabelPublic       Classification = "public"
	LabelInternal     Classification = "internal"
	LabelConfidential Classification = "confidential"
	LabelRestricted   Classification = "restricted"
)

// Rank returns the position of c in the default scheme, or -1 if unknown.
func (c Classification) Rank() int {
	switch c {
	case LabelPublic:
		return 0
	case LabelInternal:
		return 1
	case LabelConfidential:
		return 2
	case LabelRestricted:
		return 3
	}
	return -1
}

// defaultMaxClassification is the most sensitive label a backend of the given
// class may receive when the configuration does not say otherwise.
func defaultMaxClassification(c DestinationClass) Classification {
	switch c {
	case ClassInternal:
		return LabelRestricted
	case ClassApprovedExternal:
		return LabelInternal
	default:
		return LabelPublic
	}
}

// Config is the on-disk configuration (YAML). Unknown fields are rejected: in a
// security product a typo must not silently weaken a setting.
type Config struct {
	Profile  Profile        `yaml:"profile"`
	Listen   ListenConfig   `yaml:"listen"`
	Limits   LimitsConfig   `yaml:"limits"`
	Log      LogConfig      `yaml:"log"`
	Egress   EgressConfig   `yaml:"egress"`
	Database DatabaseConfig `yaml:"database"`
	Docs     DocsConfig     `yaml:"docs"`
	OIDC     OIDCConfig     `yaml:"oidc"`
	Backends []Backend      `yaml:"backends"`
	Models   []Model        `yaml:"models"`
	APIKeys  []APIKey       `yaml:"api_keys"`
}

type ListenConfig struct {
	// Data is the data-plane listener (OpenAI-compatible API).
	Data string `yaml:"data"`
	// Admin serves health, readiness and metrics. It must stay on a private
	// interface; the control-plane API will live here too.
	Admin string `yaml:"admin"`
}

type LimitsConfig struct {
	MaxRequestBytes       int64         `yaml:"max_request_bytes"`
	ReadHeaderTimeout     time.Duration `yaml:"read_header_timeout"`
	UpstreamHeaderTimeout time.Duration `yaml:"upstream_header_timeout"`
	ShutdownGrace         time.Duration `yaml:"shutdown_grace"`
}

type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// OIDCConfig enables bearer-token authentication of people and applications
// through any standards-compliant identity provider (ADR-0002). Everything
// except Mappings is fixed at startup; mappings follow configuration reloads.
type OIDCConfig struct {
	// Issuer is the exact value of the tokens' "iss" claim. Setting it turns
	// OIDC on. It is also where discovery looks for the signing keys unless
	// jwks_uri is given.
	Issuer string `yaml:"issuer"`
	// Audience must appear in the tokens' "aud" claim, so that a token issued
	// to another application of the same provider is refused.
	Audience string `yaml:"audience"`
	// DestinationClass says where the provider runs; it decides whether the
	// egress guard lets Tavian reach it under the deployment profile.
	DestinationClass DestinationClass `yaml:"destination_class"`
	// JWKSURI skips discovery and names the signing keys document directly.
	// Without it, keys are found through <issuer>/.well-known/openid-configuration.
	// The host it points to must be the issuer's or be declared here.
	JWKSURI string `yaml:"jwks_uri"`
	// JWKSRefresh is how often the signing keys are re-fetched.
	JWKSRefresh time.Duration `yaml:"jwks_refresh"`
	// JWKSMaxStaleness is how long cached keys keep being trusted when the
	// provider cannot be reached. Past it every token is refused.
	JWKSMaxStaleness time.Duration `yaml:"jwks_max_staleness"`
	// ClockSkew is the tolerance applied to exp, nbf and iat.
	ClockSkew time.Duration `yaml:"clock_skew"`
	// Algorithms lists the accepted signature algorithms (asymmetric only).
	Algorithms []string   `yaml:"algorithms"`
	Claims     OIDCClaims `yaml:"claims"`
	// Mappings turn group membership into a team and model access. A person
	// matching no mapping is authenticated but may use no model.
	Mappings []OIDCMapping `yaml:"mappings"`
}

// OIDCClaims names the claims Tavian reads.
type OIDCClaims struct {
	// Groups is the claim holding group or role names: a dotted path such as
	// "realm_access.roles" is followed through nested objects; the value is a
	// list of strings or a space-separated string. Default "groups".
	Groups string `yaml:"groups"`
	// Application is the claim naming the calling application. Default "azp".
	Application string `yaml:"application"`
}

// OIDCMapping grants access to everyone in a group.
type OIDCMapping struct {
	Group         string   `yaml:"group"`
	Team          string   `yaml:"team"`
	AllowedModels []string `yaml:"allowed_models"`
}

// DocsConfig controls the API reference served by the data plane.
type DocsConfig struct {
	// Enabled serves /docs and /openapi.yaml, without authentication. They
	// describe the API only and hold no deployment-specific information.
	// Defaults to true.
	Enabled *bool `yaml:"enabled"`
}

// DatabaseConfig locates PostgreSQL (ADR-0001). It cannot change on reload.
type DatabaseConfig struct {
	// URLEnv names the environment variable holding the connection URL, so
	// the credential never sits in the configuration file. Without it the
	// gateway runs without storage: usage events are only logged, which is
	// meant for development and is announced at startup.
	URLEnv string `yaml:"url_env"`
	// SpoolDir holds usage events while PostgreSQL is unavailable. It must be
	// on persistent storage.
	SpoolDir string `yaml:"spool_dir"`
	// SpoolMaxBytes bounds the spool; when it is full and PostgreSQL is still
	// down, new requests are refused rather than served unrecorded.
	SpoolMaxBytes int64 `yaml:"spool_max_bytes"`
	// EmitTimeout bounds one event write on the request path.
	EmitTimeout time.Duration `yaml:"emit_timeout"`
}

type EgressConfig struct {
	// InternalCIDRs defines what "internal" means for the egress guard.
	// Defaults to loopback, RFC 1918, link-local and IPv6 ULA.
	InternalCIDRs []string `yaml:"internal_cidrs"`
}

// Backend is a concrete place that can serve models.
type Backend struct {
	ID                string           `yaml:"id"`
	Type              string           `yaml:"type"` // "openai" (OpenAI-compatible, covers vLLM)
	BaseURL           string           `yaml:"base_url"`
	DestinationClass  DestinationClass `yaml:"destination_class"`
	MaxClassification Classification   `yaml:"max_classification"`
	// APIKeyEnv names the environment variable holding the credential sent to
	// the backend. Secrets are referenced, never written in the config.
	APIKeyEnv string `yaml:"api_key_env"`

	// Resolved at compile time.
	URL        *url.URL `yaml:"-"`
	Credential string   `yaml:"-"`
}

// LogValue keeps the credential out of logs even if a Backend is logged whole.
func (b *Backend) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", b.ID),
		slog.String("class", string(b.DestinationClass)),
	)
}

// Model is a name clients can request.
type Model struct {
	Name  string   `yaml:"name"`
	Type  string   `yaml:"type"` // "chat" for now
	Route []Target `yaml:"route"`
}

// Target maps a model to a backend. Only the first target is used in M1;
// strategies and failover arrive with the router (M3).
type Target struct {
	Backend       string `yaml:"backend"`
	UpstreamModel string `yaml:"upstream_model"` // defaults to the model name
}

// APIKey is a credential for an application. Only the SHA-256 of the key is
// stored. Database-backed keys replace this static list later.
type APIKey struct {
	ID            string   `yaml:"id"`
	Hash          string   `yaml:"hash"` // "sha256:<64 hex>"
	Team          string   `yaml:"team"`
	Application   string   `yaml:"application"`
	AllowedModels []string `yaml:"allowed_models"` // '*' wildcard; empty list allows nothing
}

// Load reads and parses the configuration file, returning the raw bytes too
// (they identify the revision).
func Load(path string) (*Config, []byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is chosen by the operator on the command line
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	return cfg, raw, nil
}

// Parse decodes YAML strictly and applies defaults.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("parse config: file is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen.Data == "" {
		c.Listen.Data = ":8080"
	}
	if c.Listen.Admin == "" {
		c.Listen.Admin = "127.0.0.1:9090"
	}
	if c.Limits.MaxRequestBytes == 0 {
		c.Limits.MaxRequestBytes = 4 << 20
	}
	if c.Limits.ReadHeaderTimeout == 0 {
		c.Limits.ReadHeaderTimeout = 10 * time.Second
	}
	if c.Limits.UpstreamHeaderTimeout == 0 {
		c.Limits.UpstreamHeaderTimeout = 120 * time.Second
	}
	if c.Limits.ShutdownGrace == 0 {
		c.Limits.ShutdownGrace = 30 * time.Second
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if c.OIDC.Issuer != "" {
		if c.OIDC.JWKSRefresh == 0 {
			c.OIDC.JWKSRefresh = 10 * time.Minute
		}
		if c.OIDC.JWKSMaxStaleness == 0 {
			c.OIDC.JWKSMaxStaleness = 24 * time.Hour
		}
		if c.OIDC.ClockSkew == 0 {
			c.OIDC.ClockSkew = time.Minute
		}
		if len(c.OIDC.Algorithms) == 0 {
			c.OIDC.Algorithms = []string{"RS256", "PS256", "ES256"}
		}
		if c.OIDC.Claims.Groups == "" {
			c.OIDC.Claims.Groups = "groups"
		}
		if c.OIDC.Claims.Application == "" {
			c.OIDC.Claims.Application = "azp"
		}
	}
	if c.Database.SpoolDir == "" {
		c.Database.SpoolDir = "/var/lib/tavian/spool"
	}
	if c.Database.SpoolMaxBytes == 0 {
		c.Database.SpoolMaxBytes = 64 << 20
	}
	if c.Database.EmitTimeout == 0 {
		c.Database.EmitTimeout = 2 * time.Second
	}
	if len(c.Egress.InternalCIDRs) == 0 {
		c.Egress.InternalCIDRs = DefaultInternalCIDRs()
	}
}

// DefaultInternalCIDRs lists the address ranges treated as internal.
func DefaultInternalCIDRs() []string {
	return []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fe80::/10",
		"fc00::/7",
	}
}

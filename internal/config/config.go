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
	Profile  Profile      `yaml:"profile"`
	Listen   ListenConfig `yaml:"listen"`
	Limits   LimitsConfig `yaml:"limits"`
	Log      LogConfig    `yaml:"log"`
	Egress   EgressConfig `yaml:"egress"`
	Backends []Backend    `yaml:"backends"`
	Models   []Model      `yaml:"models"`
	APIKeys  []APIKey     `yaml:"api_keys"`
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

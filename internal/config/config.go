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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/cost"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/taxonomy"
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
type DestinationClass = taxonomy.Class

const (
	ClassInternal         = taxonomy.ClassInternal
	ClassApprovedExternal = taxonomy.ClassApprovedExternal
	ClassPublicExternal   = taxonomy.ClassPublicExternal
)

// Classification is a data sensitivity label. The default scheme is ordered
// public < internal < confidential < restricted (DOMAIN_MODEL.md).
type Classification = taxonomy.Label

const (
	LabelPublic       = taxonomy.Public
	LabelInternal     = taxonomy.Internal
	LabelConfidential = taxonomy.Confidential
	LabelRestricted   = taxonomy.Restricted
)

// DefaultClearance is the label an application or group is cleared for when
// the configuration says nothing: raising it is a decision to write down.
const DefaultClearance = LabelInternal

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
	// Admin holds the credentials of the administration API (docs/ADMIN_API.md).
	// They are separate from the API keys and tokens of the data plane.
	Admin AdminConfig `yaml:"admin"`
	// Inspection configures content inspection (SECURITY.md). It is on by
	// default.
	Inspection inspect.Config `yaml:"inspection"`
	// Policy says where the policy files are (docs/POLICY.md). Without it only
	// the built-in baseline policy applies.
	Policy PolicyConfig `yaml:"policy"`
	// Quota tunes how quotas (set in policies) reserve tokens.
	Quota QuotaConfig `yaml:"quota"`
	// Audit configures the hash chain over decision records; Workers the
	// consumers of the outbox that build it. Neither changes on reload.
	Audit   AuditConfig   `yaml:"audit"`
	Workers WorkersConfig `yaml:"workers"`
	// Outbox sets how long events are kept in the database. Not reloadable.
	Outbox OutboxConfig `yaml:"outbox"`
	// Carbon is the carbon intensity of the electricity that backends use.
	Carbon   CarbonConfig `yaml:"carbon"`
	Backends []Backend    `yaml:"backends"`
	Models   []Model      `yaml:"models"`
	APIKeys  []APIKey     `yaml:"api_keys"`

	// PolicySources are the policy files read from Policy.Dir by Load. They are
	// part of the configuration revision.
	PolicySources []policy.Source `yaml:"-"`
}

// PolicyConfig locates the policy files.
type PolicyConfig struct {
	// Dir holds one or more YAML files, each with one or more policies. A
	// relative path is relative to the configuration file. Reloadable.
	Dir string `yaml:"dir"`
}

// QuotaConfig holds the settings of token reservation. Reloadable.
type QuotaConfig struct {
	// DefaultOutputTokens is what a request that sets no max_tokens is assumed
	// to need for its answer when tokens are reserved (default 1024). What the
	// answer really holds is counted when the request ends, even above it.
	DefaultOutputTokens int64 `yaml:"default_output_tokens"`
}

// MaxDefaultOutputTokens bounds quota.default_output_tokens.
const MaxDefaultOutputTokens = 1 << 20

// AuditConfig sets up the tamper-evident chain of decision records
// (docs/SECURITY.md, "Integrity"). It needs a database.
type AuditConfig struct {
	// SigningKeyFile is an Ed25519 key made by `tavian audit-keygen`. With it
	// the chain is sealed with signatures; without it the chain is still
	// built, but nothing anchors it. A relative path is relative to the
	// configuration file.
	SigningKeyFile string `yaml:"signing_key_file"`
	// SealEveryEvents and SealEvery say when a seal is made: after that many
	// new chain entries, or when the oldest unsealed entry is that old.
	// Defaults 1000 and 5m.
	SealEveryEvents int64         `yaml:"seal_every_events"`
	SealEvery       time.Duration `yaml:"seal_every"`
}

// WorkersConfig tunes the outbox consumers.
type WorkersConfig struct {
	// PollInterval is how long a consumer waits when it has caught up (default
	// 1s). BatchSize is how many events it handles at once (default 500).
	PollInterval time.Duration `yaml:"poll_interval"`
	BatchSize    int           `yaml:"batch_size"`
}

// OutboxConfig sets retention: events are removed from the outbox once they
// are older than their retention and every consumer has handled them.
type OutboxConfig struct {
	Retention RetentionConfig `yaml:"retention"`
	// PruneEvery is how often retention runs (default 1h).
	PruneEvery time.Duration `yaml:"prune_every"`
}

// RetentionConfig is how many days each kind of event is kept; 0 means for
// ever. Usage events are summed by the hour before they go (default 90 days).
// Decision records are never removed unless decision_days is set, and then only
// once a signed seal covers them, so it needs audit.signing_key_file.
type RetentionConfig struct {
	UsageDays    *int `yaml:"usage_days"`
	DecisionDays *int `yaml:"decision_days"`
}

// Keep returns the retention of each kind that has one.
func (r RetentionConfig) Keep() map[string]time.Duration {
	keep := map[string]time.Duration{}
	if r.UsageDays != nil && *r.UsageDays > 0 {
		keep["usage"] = time.Duration(*r.UsageDays) * 24 * time.Hour
	}
	if r.DecisionDays != nil && *r.DecisionDays > 0 {
		keep["decision"] = time.Duration(*r.DecisionDays) * 24 * time.Hour
	}
	return keep
}

// MaxRetentionDays bounds the retention settings.
const MaxRetentionDays = 36500

// CarbonConfig gives the carbon intensity of the grid (gCO2e per kWh) where
// backends run, entered by the operator: nothing is fetched from outside.
// Without an intensity for a backend, its requests have energy but no carbon.
// Changing it follows the configuration revision, which events record.
type CarbonConfig struct {
	// DefaultGPerKWh applies to backends without a region, or whose region is
	// not listed.
	DefaultGPerKWh *float64 `yaml:"default_g_per_kwh"`
	// Regions maps a region name (the `region` of a backend) to its intensity.
	Regions map[string]float64 `yaml:"regions"`
}

type ListenConfig struct {
	// Data is the data-plane listener (OpenAI-compatible API).
	Data string `yaml:"data"`
	// Admin serves health, readiness and metrics. It must stay on a private
	// interface; the control-plane API will live here too.
	Admin string `yaml:"admin"`
}

type LimitsConfig struct {
	MaxRequestBytes int64 `yaml:"max_request_bytes"`
	// MaxInflight caps the API requests being handled at once (streams count
	// until they end). Past it requests get 503 with Retry-After, before any
	// further work is spent on them. Default 256.
	MaxInflight           int           `yaml:"max_inflight"`
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
	// MaxClassification is the clearance this group grants (default
	// internal). Like models, clearances add up: a person gets the highest of
	// their groups.
	MaxClassification Classification `yaml:"max_classification"`
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
	// Region says where the backend runs, to find the carbon intensity of its
	// electricity in carbon.regions.
	Region string `yaml:"region"`

	// Resolved at compile time.
	URL        *url.URL `yaml:"-"`
	Credential string   `yaml:"-"`
	// CarbonGPerKWh is the intensity for this backend, nil if none is known.
	CarbonGPerKWh *float64 `yaml:"-"`
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
	// Price and Energy describe this upstream model on this backend; both are
	// optional. Without a price a request has no cost, without an energy
	// profile no energy and no carbon.
	Price  *cost.Price  `yaml:"price"`
	Energy *cost.Energy `yaml:"energy"`
}

// APIKey is a credential for an application. Only the SHA-256 of the key is
// stored. Database-backed keys replace this static list later.
type APIKey struct {
	ID            string   `yaml:"id"`
	Hash          string   `yaml:"hash"` // "sha256:<64 hex>"
	Team          string   `yaml:"team"`
	Application   string   `yaml:"application"`
	AllowedModels []string `yaml:"allowed_models"` // '*' wildcard; empty list allows nothing
	// ExpiresAt is the instant from which the key is refused (RFC 3339, or a
	// plain date meaning 00:00 UTC). Zero: the key does not expire.
	ExpiresAt time.Time `yaml:"expires_at"`
	// MaxClassification is the most sensitive label of data this application
	// is cleared to send (default internal). Enforced by the content policy.
	MaxClassification Classification `yaml:"max_classification"`
}

// AdminConfig configures the administration API on the admin listener. Without
// tokens the API is not served at all.
type AdminConfig struct {
	Tokens []AdminToken `yaml:"tokens"`
}

// AdminToken is one credential of the administration API. Its id names the
// administrator or the tool in the record of every change it makes.
type AdminToken struct {
	ID   string `yaml:"id"`
	Hash string `yaml:"hash"` // "sha256:<64 hex>", from `tavian keygen -admin`
}

// Load reads and parses the configuration file, returning the raw bytes too
// (they identify the revision).
func Load(path string) (*Config, []byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is chosen by the operator on the command line
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	dir := filepath.Dir(path)
	cfg, err := FromRevision(raw, nil, dir)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Policy.Dir != "" {
		pdir := cfg.Policy.Dir
		if !filepath.IsAbs(pdir) {
			pdir = filepath.Join(dir, pdir)
		}
		if cfg.PolicySources, err = ReadPolicyDir(pdir); err != nil {
			return nil, nil, err
		}
	}
	return cfg, raw, nil
}

// policyFileName is what a policy file of a revision may be called: a plain
// file name as ReadPolicyDir finds it (no directory part, not hidden), so that
// exporting a revision to a directory cannot write anywhere else.
var policyFileName = regexp.MustCompile(`^[^/\\\x00-\x1f.][^/\\\x00-\x1f]*\.ya?ml$`)

// ValidPolicyFileName says whether name is a plain policy file name: no
// directory part, not hidden, ending in .yaml or .yml.
func ValidPolicyFileName(name string) bool { return policyFileName.MatchString(name) }

// FromRevision builds a Config from the stored form of a revision: the YAML
// and the policy files it was made from (the ones Load reads from policy.dir).
// dir is where relative paths of the configuration are resolved from, the
// directory of the configuration file the gateway started with.
func FromRevision(raw []byte, policies []policy.Source, dir string) (*Config, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if k := cfg.Audit.SigningKeyFile; k != "" && !filepath.IsAbs(k) {
		cfg.Audit.SigningKeyFile = filepath.Join(dir, k)
	}
	seen := map[string]bool{}
	for _, p := range policies {
		if !ValidPolicyFileName(p.Name) {
			return nil, fmt.Errorf("policy file %q: the name must be a plain file name ending in .yaml or .yml", p.Name)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("policy file %q: given twice", p.Name)
		}
		seen[p.Name] = true
	}
	cfg.PolicySources = policies
	return cfg, nil
}

// ReadPolicyDir reads the *.yaml and *.yml files of dir, not recursively,
// ignoring hidden files.
func ReadPolicyDir(dir string) ([]policy.Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("policy.dir: %w", err)
	}
	var out []policy.Source
	for _, e := range entries {
		name := e.Name()
		ext := filepath.Ext(name)
		if e.IsDir() || strings.HasPrefix(name, ".") || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory is chosen by the operator in the configuration
		if err != nil {
			return nil, fmt.Errorf("policy.dir: %w", err)
		}
		out = append(out, policy.Source{Name: name, Raw: raw})
	}
	return out, nil
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
	if c.Limits.MaxInflight == 0 {
		c.Limits.MaxInflight = 256
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
	c.Inspection.ApplyDefaults()
	if c.Quota.DefaultOutputTokens == 0 {
		c.Quota.DefaultOutputTokens = 1024
	}
	if c.Audit.SealEveryEvents == 0 {
		c.Audit.SealEveryEvents = 1000
	}
	if c.Audit.SealEvery == 0 {
		c.Audit.SealEvery = 5 * time.Minute
	}
	if c.Workers.PollInterval == 0 {
		c.Workers.PollInterval = time.Second
	}
	if c.Workers.BatchSize == 0 {
		c.Workers.BatchSize = 500
	}
	if c.Outbox.Retention.UsageDays == nil {
		d := 90
		c.Outbox.Retention.UsageDays = &d
	}
	if c.Outbox.Retention.DecisionDays == nil {
		d := 0
		c.Outbox.Retention.DecisionDays = &d
	}
	if c.Outbox.PruneEvery == 0 {
		c.Outbox.PruneEvery = time.Hour
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
	for i := range c.APIKeys {
		if c.APIKeys[i].MaxClassification == "" {
			c.APIKeys[i].MaxClassification = DefaultClearance
		}
	}
	for i := range c.OIDC.Mappings {
		if c.OIDC.Mappings[i].MaxClassification == "" {
			c.OIDC.Mappings[i].MaxClassification = DefaultClearance
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

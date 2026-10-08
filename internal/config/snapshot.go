package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Snapshot is an immutable, validated view of the configuration, identified by
// a revision. Every decision and usage event references the revision it was
// produced under. Never mutate a Snapshot after Compile returns.
type Snapshot struct {
	Revision string
	LoadedAt time.Time
	Profile  Profile
	Limits   LimitsConfig

	Backends map[string]*Backend
	Models   map[string]*Model
	// ModelNames is Models' keys, sorted, for stable listings.
	ModelNames []string
	// Keys indexes API keys by the hex SHA-256 of the key.
	Keys map[string]*APIKey
	// Endpoints is the egress allow-list: "host:port" -> destination class.
	Endpoints map[string]DestinationClass
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// EndpointKey normalises a backend URL to the "host:port" form the egress
// guard matches on.
func EndpointKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// Compile validates cfg and builds a Snapshot. raw is the exact configuration
// bytes (used to derive the revision); getenv resolves credential references.
// All problems are reported together.
func Compile(cfg *Config, raw []byte, getenv func(string) string) (*Snapshot, error) {
	var errs []error
	addf := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch cfg.Profile {
	case ProfileAirGapped, ProfileControlledEgress, ProfileOpenEgress:
	case "":
		addf("profile: required (air-gapped, controlled-egress or open-egress)")
	default:
		addf("profile: unknown value %q", cfg.Profile)
	}

	if cfg.Database.URLEnv != "" && getenv(cfg.Database.URLEnv) == "" {
		addf("database.url_env: environment variable %s is not set", cfg.Database.URLEnv)
	}
	if cfg.Database.SpoolMaxBytes < 1<<20 {
		addf("database.spool_max_bytes: must be at least 1048576 (1 MiB)")
	}

	sum := sha256.Sum256(raw)
	s := &Snapshot{
		Revision:  hex.EncodeToString(sum[:])[:12],
		LoadedAt:  time.Now().UTC(),
		Profile:   cfg.Profile,
		Limits:    cfg.Limits,
		Backends:  map[string]*Backend{},
		Models:    map[string]*Model{},
		Keys:      map[string]*APIKey{},
		Endpoints: map[string]DestinationClass{},
	}

	for i := range cfg.Backends {
		b := cfg.Backends[i]
		where := fmt.Sprintf("backends[%d]", i)
		if !idPattern.MatchString(b.ID) {
			addf("%s: id %q must match %s", where, b.ID, idPattern)
			continue
		}
		where = fmt.Sprintf("backend %q", b.ID)
		if _, dup := s.Backends[b.ID]; dup {
			addf("%s: duplicate id", where)
			continue
		}
		if b.Type != "openai" {
			addf("%s: unsupported type %q (supported: openai)", where, b.Type)
		}
		switch b.DestinationClass {
		case ClassInternal, ClassApprovedExternal, ClassPublicExternal:
			if !cfg.Profile.allows(b.DestinationClass) && cfg.Profile != "" {
				addf("%s: destination_class %q is not allowed by profile %q", where, b.DestinationClass, cfg.Profile)
			}
		default:
			addf("%s: destination_class must be internal, approved-external or public-external (got %q)", where, b.DestinationClass)
		}
		if b.MaxClassification == "" {
			b.MaxClassification = defaultMaxClassification(b.DestinationClass)
		} else if b.MaxClassification.Rank() < 0 {
			addf("%s: unknown max_classification %q", where, b.MaxClassification)
		}

		u, err := url.Parse(b.BaseURL)
		switch {
		case err != nil || u.Host == "":
			addf("%s: base_url %q is not a valid absolute URL", where, b.BaseURL)
		case u.Scheme != "http" && u.Scheme != "https":
			addf("%s: base_url scheme must be http or https", where)
		case u.User != nil || u.RawQuery != "" || u.Fragment != "":
			addf("%s: base_url must not contain credentials, query or fragment", where)
		default:
			b.URL = u
			key := EndpointKey(u)
			if prev, ok := s.Endpoints[key]; ok && prev != b.DestinationClass {
				addf("%s: endpoint %s is already declared with class %q", where, key, prev)
			}
			s.Endpoints[key] = b.DestinationClass
		}

		if b.APIKeyEnv != "" {
			if b.Credential = getenv(b.APIKeyEnv); b.Credential == "" {
				addf("%s: environment variable %s (api_key_env) is empty or unset", where, b.APIKeyEnv)
			}
		}
		s.Backends[b.ID] = &b
	}

	for i := range cfg.Models {
		m := cfg.Models[i]
		if m.Name == "" {
			addf("models[%d]: name required", i)
			continue
		}
		where := fmt.Sprintf("model %q", m.Name)
		if _, dup := s.Models[m.Name]; dup {
			addf("%s: duplicate name", where)
			continue
		}
		if m.Type != "chat" {
			addf("%s: unsupported type %q (supported: chat)", where, m.Type)
		}
		if len(m.Route) == 0 {
			addf("%s: route must list at least one backend", where)
		}
		route := make([]Target, len(m.Route))
		for j, t := range m.Route {
			if _, ok := s.Backends[t.Backend]; !ok {
				addf("%s: route[%d] references unknown backend %q", where, j, t.Backend)
			}
			if t.UpstreamModel == "" {
				t.UpstreamModel = m.Name
			}
			route[j] = t
		}
		m.Route = route
		s.Models[m.Name] = &m
		s.ModelNames = append(s.ModelNames, m.Name)
	}
	sort.Strings(s.ModelNames)

	for i := range cfg.APIKeys {
		k := cfg.APIKeys[i]
		where := fmt.Sprintf("api_keys[%d]", i)
		if !idPattern.MatchString(k.ID) {
			addf("%s: id %q must match %s", where, k.ID, idPattern)
			continue
		}
		where = fmt.Sprintf("api key %q", k.ID)
		h, ok := strings.CutPrefix(strings.ToLower(k.Hash), "sha256:")
		if !ok || len(h) != 64 {
			addf("%s: hash must be \"sha256:\" followed by 64 hex characters (use `tavian keygen`)", where)
			continue
		}
		if _, err := hex.DecodeString(h); err != nil {
			addf("%s: hash is not valid hex", where)
			continue
		}
		if _, dup := s.Keys[h]; dup {
			addf("%s: duplicate hash", where)
			continue
		}
		if len(k.AllowedModels) == 0 {
			addf("%s: allowed_models must list at least one pattern (an empty list would allow nothing)", where)
		}
		s.Keys[h] = &k
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n%w", errors.Join(errs...))
	}
	return s, nil
}

// Holder publishes the current Snapshot to the data plane. Swaps are atomic;
// readers always see a complete, validated snapshot.
type Holder struct{ p atomic.Pointer[Snapshot] }

// Load returns the current snapshot, or nil if none has been stored.
func (h *Holder) Load() *Snapshot { return h.p.Load() }

// Store publishes s.
func (h *Holder) Store(s *Snapshot) { h.p.Store(s) }

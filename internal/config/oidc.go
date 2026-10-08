package config

import (
	"fmt"
	"net/url"
	"slices"
)

// Signature algorithms accepted for tokens: asymmetric only. HMAC would let
// anyone who knows the public key forge tokens.
var allowedAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// compileOIDC validates cfg.OIDC and declares its endpoints to the egress guard.
func compileOIDC(cfg *Config, s *Snapshot, addf func(string, ...any)) {
	o := cfg.OIDC
	if o.Audience == "" {
		addf("oidc.audience: required (without it a token issued to any other application of the provider would be accepted)")
	}
	switch o.DestinationClass {
	case ClassInternal, ClassApprovedExternal, ClassPublicExternal:
		if cfg.Profile != "" && !cfg.Profile.allows(o.DestinationClass) {
			addf("oidc.destination_class %q is not allowed by profile %q", o.DestinationClass, cfg.Profile)
		}
	default:
		addf("oidc.destination_class must be internal, approved-external or public-external (got %q)", o.DestinationClass)
	}

	declare := func(field, raw string) {
		u, err := url.Parse(raw)
		switch {
		case err != nil || u.Host == "":
			addf("%s: %q is not a valid absolute URL", field, raw)
		case u.Scheme != "https" && (u.Scheme != "http" || o.DestinationClass != ClassInternal):
			addf("%s: must be https (plain http is only accepted for an internal provider)", field)
		case u.User != nil || u.RawQuery != "" || u.Fragment != "":
			addf("%s: must not contain credentials, query or fragment", field)
		default:
			key := EndpointKey(u)
			if prev, ok := s.Endpoints[key]; ok && prev != o.DestinationClass {
				addf("%s: endpoint %s is already declared with class %q", field, key, prev)
			}
			s.Endpoints[key] = o.DestinationClass
		}
	}
	// The issuer is first of all an identifier (the tokens' "iss"); it is only
	// contacted, for discovery, when no jwks_uri is given.
	if o.JWKSURI != "" {
		declare("oidc.jwks_uri", o.JWKSURI)
		if u, err := url.Parse(o.Issuer); err != nil || u.Host == "" {
			addf("oidc.issuer: %q is not a valid absolute URL", o.Issuer)
		}
	} else {
		declare("oidc.issuer", o.Issuer)
	}

	for _, a := range o.Algorithms {
		if !slices.Contains(allowedAlgorithms, a) {
			addf("oidc.algorithms: %q is not accepted (use asymmetric algorithms: %v)", a, allowedAlgorithms)
		}
	}
	if o.JWKSMaxStaleness < o.JWKSRefresh {
		addf("oidc.jwks_max_staleness must not be shorter than jwks_refresh")
	}

	seen := map[string]bool{}
	for i, m := range o.Mappings {
		where := fmt.Sprintf("oidc.mappings[%d]", i)
		switch {
		case m.Group == "":
			addf("%s: group is required", where)
		case seen[m.Group]:
			addf("%s: group %q is mapped twice", where, m.Group)
		}
		seen[m.Group] = true
		if !idPattern.MatchString(m.Team) {
			addf("%s: team %q must match %s", where, m.Team, idPattern)
		}
		if len(m.AllowedModels) == 0 {
			addf("%s: allowed_models must list at least one pattern", where)
		}
		if m.MaxClassification.Rank() < 0 {
			addf("%s: unknown max_classification %q", where, m.MaxClassification)
		}
	}
}

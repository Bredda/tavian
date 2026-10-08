package auth

import (
	"net/http"
	"slices"
	"strings"

	"github.com/bredda/tavian/internal/config"
)

// OIDCAuthenticator accepts OIDC access tokens. Who the token proves is the
// verifier's business; what that person may do comes from the configuration's
// group mappings, read from the current snapshot so that a reload takes effect
// on the next request.
type OIDCAuthenticator struct {
	Snap     *config.Holder
	Verifier *JWTVerifier
}

func (a OIDCAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	token, ok := bearer(r)
	if !ok {
		return nil, unauthenticated("no bearer credential")
	}
	claims, err := a.Verifier.Verify(r.Context(), token)
	if err != nil {
		return nil, unauthenticated(err.Error())
	}
	s := a.Snap.Load()
	if s == nil {
		return nil, ErrUnauthenticated
	}

	// The first matching mapping (in configuration order) names the team; the
	// allowed models and the clearance of every matching mapping add up.
	id := &Identity{Subject: claims.Subject, Application: claims.Application, Method: "oidc", MaxClassification: config.LabelPublic}
	for _, m := range s.OIDC.Mappings {
		if !slices.Contains(claims.Groups, m.Group) {
			continue
		}
		if id.Team == "" {
			id.Team = m.Team
		}
		if m.MaxClassification.Rank() > id.MaxClassification.Rank() {
			id.MaxClassification = m.MaxClassification
		}
		for _, p := range m.AllowedModels {
			if !slices.Contains(id.AllowedModels, p) {
				id.AllowedModels = append(id.AllowedModels, p)
			}
		}
	}
	return id, nil
}

// Chain picks the authenticator for a request from its credential: Tavian API
// keys carry the "tav_" prefix, anything else is offered to OIDC when that is
// configured.
type Chain struct {
	APIKey Authenticator
	OIDC   Authenticator // nil when OIDC is off
}

func (c Chain) Authenticate(r *http.Request) (*Identity, error) {
	token, ok := bearer(r)
	switch {
	case !ok:
		return nil, unauthenticated("no bearer credential")
	case strings.HasPrefix(token, KeyPrefix) || c.OIDC == nil:
		return c.APIKey.Authenticate(r)
	default:
		return c.OIDC.Authenticate(r)
	}
}

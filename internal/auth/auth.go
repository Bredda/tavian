// Package auth turns an incoming request into an Identity: from a Tavian API
// key, or from an OIDC access token issued by the organisation's identity
// provider (ADR-0002). Both sit behind the Authenticator interface.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/glob"
)

// ErrUnauthenticated is returned when no valid credential is presented. The
// error may carry a reason (see Reason) for the operator's logs; it is
// deliberately never shown to the caller.
var ErrUnauthenticated = errors.New("unauthenticated")

// Reason returns the operator-facing explanation attached to an
// authentication failure, if any.
func Reason(err error) string {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, ErrUnauthenticated.Error()+": "); ok {
		return rest
	}
	return ""
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, reason)
}

// bearer returns the token of an "Authorization: Bearer <token>" header.
func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// Admin is the authenticated principal of the administration API: the token's
// id, which names the author of every change it makes, and its role.
type Admin struct {
	TokenID string
	Role    config.Role
}

// AdminAuthenticator validates `Authorization: Bearer <token>` against the
// administration tokens of the current config snapshot. Data-plane API keys
// and OIDC tokens are not accepted, and administration tokens are not
// accepted by the data plane (they are not in its key table).
type AdminAuthenticator struct {
	Snap *config.Holder
	Now  func() time.Time // for tests; defaults to time.Now
}

// Authenticate returns the administrator behind r, or an ErrUnauthenticated.
func (a AdminAuthenticator) Authenticate(r *http.Request) (*Admin, error) {
	s := a.Snap.Load()
	if s == nil {
		return nil, ErrUnauthenticated
	}
	token, ok := bearer(r)
	if !ok {
		return nil, unauthenticated("no bearer credential")
	}
	t, ok := s.AdminTokens[HashKey(token)]
	if !ok {
		return nil, unauthenticated("unknown admin token")
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if t.Expired(now()) {
		// the caller is told no more than for an unknown token; the log names it
		return nil, unauthenticated("admin token " + t.ID + " expired")
	}
	return &Admin{TokenID: t.ID, Role: t.Role}, nil
}

// Identity is the authenticated principal, the input to every later decision.
type Identity struct {
	// KeyID identifies the API key, when one was used.
	KeyID string
	// Subject is the identity provider's stable identifier of the person or
	// service account, when a token was used.
	Subject string
	// Groups are the groups the identity provider reported (OIDC only).
	Groups        []string
	Team          string
	Application   string
	AllowedModels []string
	// MaxClassification is the most sensitive label of data the caller is
	// cleared to send.
	MaxClassification config.Classification
	Method            string // "api_key" | "oidc"
}

// CanUseModel reports whether the identity may request the named model.
func (i *Identity) CanUseModel(model string) bool {
	return glob.MatchAny(i.AllowedModels, model)
}

// Authenticator extracts an Identity from a request.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

// APIKeyAuthenticator validates `Authorization: Bearer <key>` against the keys
// of the current config snapshot.
type APIKeyAuthenticator struct {
	Snap *config.Holder
	Now  func() time.Time // for tests; defaults to time.Now
}

func (a APIKeyAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	s := a.Snap.Load()
	if s == nil {
		return nil, ErrUnauthenticated
	}
	token, ok := bearer(r)
	if !ok {
		return nil, unauthenticated("no bearer credential")
	}
	k, ok := s.Keys[HashKey(token)]
	if !ok {
		return nil, unauthenticated("unknown API key")
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if !k.ExpiresAt.IsZero() && !now().Before(k.ExpiresAt) {
		return nil, unauthenticated("API key " + k.ID + " expired")
	}
	return &Identity{
		KeyID:             k.ID,
		Team:              k.Team,
		Application:       k.Application,
		AllowedModels:     k.AllowedModels,
		MaxClassification: k.MaxClassification,
		Method:            "api_key",
	}, nil
}

// HashKey returns the hex SHA-256 of an API key. Keys are 256-bit random
// values, so a fast unsalted hash is sufficient (there is nothing to brute
// force) and keeps authentication cheap on the hot path.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// KeyPrefix marks Tavian API keys so they are easy to spot in secret scanners.
const KeyPrefix = "tav_"

// AdminTokenPrefix marks the tokens of the administration API, which are not
// interchangeable with API keys.
const AdminTokenPrefix = "tavadm_"

// GenerateKey returns a new random API key and the config value to store for it.
func GenerateKey() (key, configHash string, err error) {
	return generate(KeyPrefix)
}

// GenerateAdminToken returns a new random administration token and the config
// value to store for it.
func GenerateAdminToken() (token, configHash string, err error) {
	return generate(AdminTokenPrefix)
}

func generate(prefix string) (secret, configHash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	secret = prefix + base64.RawURLEncoding.EncodeToString(b[:])
	return secret, "sha256:" + HashKey(secret), nil
}

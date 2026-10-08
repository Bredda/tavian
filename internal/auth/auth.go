// Package auth turns an incoming request into an Identity. M1 supports API
// keys; OIDC (ADR-0002) plugs in behind the same Authenticator interface.
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

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/glob"
)

// ErrUnauthenticated is returned when no valid credential is presented. The
// reason is deliberately not exposed to the caller.
var ErrUnauthenticated = errors.New("unauthenticated")

// Identity is the authenticated principal, the input to every later decision.
type Identity struct {
	KeyID         string
	Team          string
	Application   string
	AllowedModels []string
	Method        string // "api_key"
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
type APIKeyAuthenticator struct{ Snap *config.Holder }

func (a APIKeyAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	s := a.Snap.Load()
	if s == nil {
		return nil, ErrUnauthenticated
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return nil, ErrUnauthenticated
	}
	k, ok := s.Keys[HashKey(strings.TrimSpace(token))]
	if !ok {
		return nil, ErrUnauthenticated
	}
	return &Identity{
		KeyID:         k.ID,
		Team:          k.Team,
		Application:   k.Application,
		AllowedModels: k.AllowedModels,
		Method:        "api_key",
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

// GenerateKey returns a new random API key and the config value to store for it.
func GenerateKey() (key, configHash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	key = KeyPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return key, "sha256:" + HashKey(key), nil
}

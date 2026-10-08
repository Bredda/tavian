package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/bredda/tavian/internal/config"
)

// maxIdPResponse bounds what is read from the identity provider.
const maxIdPResponse = 1 << 20

// refetchCooldown limits how often an unknown key id may trigger a re-fetch,
// so a stream of forged tokens cannot turn the gateway into a client that
// hammers the provider.
const refetchCooldown = 10 * time.Second

// Claims are the validated contents of a token.
type Claims struct {
	Subject     string
	Groups      []string
	Application string
}

// keyState is an immutable set of signing keys and when it was fetched.
type keyState struct {
	keys      []jose.JSONWebKey
	fetchedAt time.Time
}

// JWTVerifier validates OIDC access tokens against the provider's signing
// keys, which it fetches through the egress-guarded client, caches, and
// refreshes in the background (ADR-0002).
//
// While the provider is unreachable, cached keys keep being trusted for up to
// JWKSMaxStaleness; after that every token is refused. A token signed with a
// key id the cache does not know triggers one re-fetch (rate-limited) to
// follow key rotation, and is refused if that does not help.
type JWTVerifier struct {
	cfg  config.OIDCConfig
	http *http.Client
	log  *slog.Logger
	now  func() time.Time

	algs  []jose.SignatureAlgorithm
	state atomic.Pointer[keyState]

	mu        sync.Mutex // serialises fetches
	lastFetch time.Time
	jwksURI   string // from config or discovery
}

// NewJWTVerifier returns a verifier. Call Run to keep its keys fresh.
func NewJWTVerifier(cfg config.OIDCConfig, hc *http.Client, log *slog.Logger) *JWTVerifier {
	v := &JWTVerifier{cfg: cfg, http: hc, log: log, now: time.Now, jwksURI: cfg.JWKSURI}
	for _, a := range cfg.Algorithms {
		v.algs = append(v.algs, jose.SignatureAlgorithm(a))
	}
	return v
}

// Run fetches the keys, then refreshes them until ctx is done. A provider that
// is down at startup is not fatal: tokens are refused until the first fetch
// succeeds, and the fetch is retried with backoff.
func (v *JWTVerifier) Run(ctx context.Context) {
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := v.refresh(fctx)
		cancel()
		if err != nil {
			wait = min(max(2*wait, 5*time.Second), time.Minute)
			v.log.Warn("could not refresh the identity provider's signing keys", "error", err, "retry_in", wait.String())
			continue
		}
		wait = v.cfg.JWKSRefresh
	}
}

// KeysAge returns how old the cached keys are, or -1 if there are none.
func (v *JWTVerifier) KeysAge() time.Duration {
	st := v.state.Load()
	if st == nil {
		return -1
	}
	return v.now().Sub(st.fetchedAt)
}

// refresh fetches the key set and, on success, replaces the cache.
func (v *JWTVerifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.refreshLocked(ctx)
}

func (v *JWTVerifier) refreshLocked(ctx context.Context) error {
	v.lastFetch = v.now()
	if v.jwksURI == "" {
		uri, err := v.discover(ctx)
		if err != nil {
			return err
		}
		v.jwksURI = uri
	}
	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, v.jwksURI, &set); err != nil {
		return fmt.Errorf("fetch signing keys: %w", err)
	}
	var keys []jose.JSONWebKey
	for _, k := range set.Keys {
		// Only verification keys: public, and not reserved for encryption.
		if k.IsPublic() && k.Valid() && (k.Use == "" || k.Use == "sig") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return errors.New("fetch signing keys: the document holds no usable signing key")
	}
	v.state.Store(&keyState{keys: keys, fetchedAt: v.now()})
	v.log.Info("identity provider signing keys loaded", "keys", len(keys))
	return nil
}

// discover reads the provider's metadata and returns its jwks_uri.
func (v *JWTVerifier) discover(ctx context.Context) (string, error) {
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	url := strings.TrimSuffix(v.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	if err := v.getJSON(ctx, url, &meta); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	// RFC 8414 §3.3: a mismatch means the document is not about this issuer.
	if meta.Issuer != v.cfg.Issuer {
		return "", fmt.Errorf("discovery: document is for issuer %q, not %q", meta.Issuer, v.cfg.Issuer)
	}
	if meta.JWKSURI == "" {
		return "", errors.New("discovery: no jwks_uri")
	}
	return meta.JWKSURI, nil
}

func (v *JWTVerifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponse+1))
	if err != nil {
		return err
	}
	if len(body) > maxIdPResponse {
		return fmt.Errorf("%s: response too large", url)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}

// Verify checks a compact-serialised token and returns its claims. The error
// text says why it failed and never contains the token.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, v.algs)
	if err != nil {
		return nil, errors.New("not a valid signed token, or an algorithm that is not accepted")
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("token must have exactly one signature")
	}
	hdr := tok.Headers[0]

	key, err := v.keyFor(ctx, hdr)
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	var all map[string]any
	if err := tok.Claims(key.Key, &std, &all); err != nil {
		return nil, errors.New("signature does not verify")
	}

	if std.Expiry == nil {
		return nil, errors.New("token has no expiry")
	}
	err = std.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.cfg.Issuer,
		AnyAudience: []string{v.cfg.Audience},
		Time:        v.now(),
	}, v.cfg.ClockSkew)
	switch {
	case err == nil:
	case errors.Is(err, jwt.ErrExpired):
		return nil, errors.New("token expired")
	case errors.Is(err, jwt.ErrNotValidYet), errors.Is(err, jwt.ErrIssuedInTheFuture):
		return nil, errors.New("token not valid yet")
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return nil, errors.New("wrong issuer")
	case errors.Is(err, jwt.ErrInvalidAudience):
		return nil, errors.New("wrong audience")
	default:
		return nil, errors.New("invalid claims")
	}
	if std.Subject == "" {
		return nil, errors.New("token has no subject")
	}

	app, _ := all[v.cfg.Claims.Application].(string)
	return &Claims{
		Subject:     std.Subject,
		Groups:      claimStrings(all, v.cfg.Claims.Groups),
		Application: app,
	}, nil
}

// keyFor picks the signing key named by the token header, re-fetching the key
// set once if the id is unknown.
func (v *JWTVerifier) keyFor(ctx context.Context, hdr jose.Header) (*jose.JSONWebKey, error) {
	st := v.state.Load()
	if st == nil {
		return nil, errors.New("signing keys of the identity provider are not available")
	}
	if age := v.now().Sub(st.fetchedAt); age > v.cfg.JWKSMaxStaleness {
		return nil, fmt.Errorf("signing keys are %s old, beyond the allowed staleness", age.Round(time.Second))
	}
	if k := pick(st.keys, hdr); k != nil {
		return k, nil
	}

	// Unknown key id: the provider may have rotated its keys.
	v.mu.Lock()
	if v.now().Sub(v.lastFetch) >= refetchCooldown {
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := v.refreshLocked(fctx); err != nil {
			v.log.Warn("could not re-fetch signing keys for an unknown key id", "error", err)
		}
		cancel()
	}
	v.mu.Unlock()
	if st = v.state.Load(); st != nil {
		if k := pick(st.keys, hdr); k != nil {
			return k, nil
		}
	}
	return nil, errors.New("token is signed with an unknown key")
}

// pick returns the key matching the header's key id and algorithm. Without a
// key id it accepts a key only if exactly one fits.
func pick(keys []jose.JSONWebKey, hdr jose.Header) *jose.JSONWebKey {
	var match []*jose.JSONWebKey
	for i := range keys {
		k := &keys[i]
		if hdr.KeyID != "" && k.KeyID != hdr.KeyID {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != hdr.Algorithm {
			continue
		}
		match = append(match, k)
	}
	if len(match) == 1 {
		return match[0]
	}
	return nil
}

// claimStrings reads a list of strings from a claim. path may be dotted
// ("realm_access.roles") to descend into nested objects; a space-separated
// string is accepted too (OAuth "scope" style).
func claimStrings(claims map[string]any, path string) []string {
	if v, ok := claims[path]; ok { // a claim whose name itself contains dots
		return stringList(v)
	}
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return stringList(cur)
}

func stringList(cur any) []string {
	switch v := cur.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Fields(v)
	}
	return nil
}

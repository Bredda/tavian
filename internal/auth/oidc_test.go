package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/bredda/tavian/internal/config"
)

const (
	testIssuer   = "https://idp.example/realms/tavian"
	testAudience = "tavian"
)

// fakeIdP serves a discovery document and a JWKS, and counts the fetches.
type fakeIdP struct {
	srv *httptest.Server

	mu        sync.Mutex
	keys      []jose.JSONWebKey // public
	down      bool
	jwksHits  int
	discHits  int
	issuerDoc string // issuer reported by discovery
}

func newFakeIdP(t *testing.T, keys ...jose.JSONWebKey) *fakeIdP {
	t.Helper()
	f := &fakeIdP{keys: keys, issuerDoc: testIssuer}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/tavian/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.discHits++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.issuerDoc, "jwks_uri": f.srv.URL + "/certs"})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.jwksHits++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: f.keys})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) set(fn func(*fakeIdP)) { f.mu.Lock(); fn(f); f.mu.Unlock() }
func (f *fakeIdP) hits() int             { f.mu.Lock(); defer f.mu.Unlock(); return f.jwksHits }

type signer struct {
	key jose.JSONWebKey // private
	alg jose.SignatureAlgorithm
}

func (s signer) public() jose.JSONWebKey { return s.key.Public() }

func rsaSigner(t *testing.T, kid string) signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{jose.JSONWebKey{Key: k, KeyID: kid, Use: "sig", Algorithm: "RS256"}, jose.RS256}
}

func ecSigner(t *testing.T, kid string) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{jose.JSONWebKey{Key: k, KeyID: kid, Use: "sig", Algorithm: "ES256"}, jose.ES256}
}

func (s signer) sign(t *testing.T, std jwt.Claims, extra map[string]any) string {
	t.Helper()
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.key.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	b := jwt.Signed(sg).Claims(std)
	if extra != nil {
		b = b.Claims(extra)
	}
	raw, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var epoch = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func goodClaims() jwt.Claims {
	return jwt.Claims{
		Issuer:   testIssuer,
		Subject:  "user-123",
		Audience: jwt.Audience{testAudience},
		Expiry:   jwt.NewNumericDate(epoch.Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(epoch),
	}
}

func oidcConfig(mut ...func(*config.OIDCConfig)) config.OIDCConfig {
	c := config.OIDCConfig{
		Issuer:           testIssuer,
		Audience:         testAudience,
		JWKSRefresh:      time.Hour,
		JWKSMaxStaleness: 24 * time.Hour,
		ClockSkew:        time.Minute,
		Algorithms:       []string{"RS256", "ES256"},
		Claims:           config.OIDCClaims{Groups: "groups", Application: "azp"},
	}
	for _, m := range mut {
		m(&c)
	}
	return c
}

// newVerifier returns a verifier on a controllable clock whose keys were
// fetched from f.
func newVerifier(t *testing.T, f *fakeIdP, cfg config.OIDCConfig) (*JWTVerifier, *time.Time) {
	t.Helper()
	if cfg.JWKSURI == "" {
		cfg.Issuer = testIssuer // discovery is under the fake's URL, see rewrite below
	}
	v := NewJWTVerifier(cfg, f.srv.Client(), slog.New(slog.DiscardHandler))
	// The fake serves plain http on a random port: point discovery at it
	// while keeping the issuer string the tokens carry.
	v.http = &http.Client{Transport: rewrite{target: f.srv.URL, rt: http.DefaultTransport}}
	now := epoch
	v.now = func() time.Time { return now }
	if err := v.refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	return v, &now
}

// rewrite sends every request to the fake server, whatever its URL says.
type rewrite struct {
	target string
	rt     http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	t, _ := http.NewRequest(req.Method, r.target, nil)
	u.Scheme, u.Host = t.URL.Scheme, t.URL.Host
	req2 := req.Clone(req.Context())
	req2.URL = &u
	return r.rt.RoundTrip(req2)
}

func mustReject(t *testing.T, v *JWTVerifier, raw, wantInReason string) {
	t.Helper()
	_, err := v.Verify(context.Background(), raw)
	if err == nil {
		t.Fatalf("token accepted, want rejection containing %q", wantInReason)
	}
	if !strings.Contains(err.Error(), wantInReason) {
		t.Errorf("reason = %q, want it to contain %q", err, wantInReason)
	}
	if strings.Contains(err.Error(), raw) {
		t.Error("the error leaks the token")
	}
}

func TestVerifyAcceptsValidTokens(t *testing.T) {
	rs, ec := rsaSigner(t, "rs-1"), ecSigner(t, "ec-1")
	f := newFakeIdP(t, rs.public(), ec.public())
	v, _ := newVerifier(t, f, oidcConfig())

	for name, s := range map[string]signer{"RS256": rs, "ES256": ec} {
		raw := s.sign(t, goodClaims(), map[string]any{"groups": []string{"ai-research", "admins"}, "azp": "notebook"})
		c, err := v.Verify(context.Background(), raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Subject != "user-123" || c.Application != "notebook" || len(c.Groups) != 2 || c.Groups[0] != "ai-research" {
			t.Errorf("%s: claims = %+v", name, c)
		}
	}
}

func TestVerifyRejectsBadClaims(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())

	cases := map[string]struct {
		mut    func(*jwt.Claims)
		reason string
	}{
		"expired":        {func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(epoch.Add(-2 * time.Minute)) }, "expired"},
		"not yet valid":  {func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(epoch.Add(10 * time.Minute)) }, "not valid yet"},
		"wrong audience": {func(c *jwt.Claims) { c.Audience = jwt.Audience{"account"} }, "audience"},
		"no audience":    {func(c *jwt.Claims) { c.Audience = nil }, "audience"},
		"wrong issuer":   {func(c *jwt.Claims) { c.Issuer = "https://evil.example/realms/tavian" }, "issuer"},
		"no expiry":      {func(c *jwt.Claims) { c.Expiry = nil }, "no expiry"},
		"no subject":     {func(c *jwt.Claims) { c.Subject = "" }, "no subject"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := goodClaims()
			tc.mut(&c)
			mustReject(t, v, rs.sign(t, c, nil), tc.reason)
		})
	}

	t.Run("expiry within the clock skew is tolerated", func(t *testing.T) {
		c := goodClaims()
		c.Expiry = jwt.NewNumericDate(epoch.Add(-30 * time.Second))
		if _, err := v.Verify(context.Background(), rs.sign(t, c, nil)); err != nil {
			t.Errorf("rejected within skew: %v", err)
		}
	})
}

func TestVerifyRejectsForgeries(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	attacker := rsaSigner(t, "rs-1") // same kid, other key
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())

	t.Run("signed with another key", func(t *testing.T) {
		mustReject(t, v, attacker.sign(t, goodClaims(), nil), "signature")
	})

	t.Run("payload tampered with", func(t *testing.T) {
		parts := strings.Split(rs.sign(t, goodClaims(), nil), ".")
		other := strings.Split(rs.sign(t, func() jwt.Claims { c := goodClaims(); c.Subject = "admin"; return c }(), nil), ".")
		mustReject(t, v, parts[0]+"."+other[1]+"."+parts[2], "signature")
	})

	t.Run("alg none", func(t *testing.T) {
		enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		raw := enc(`{"alg":"none","typ":"JWT"}`) + "." + enc(`{"iss":"`+testIssuer+`","sub":"x","aud":"tavian","exp":4102444800}`) + "."
		mustReject(t, v, raw, "not accepted")
	})

	t.Run("HMAC with the public key as secret", func(t *testing.T) {
		sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("public-key-bytes-as-secret-0123456789")},
			(&jose.SignerOptions{}).WithHeader("kid", "rs-1"))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := jwt.Signed(sg).Claims(goodClaims()).Serialize()
		mustReject(t, v, raw, "not accepted")
	})

	t.Run("garbage", func(t *testing.T) {
		for _, raw := range []string{"abc", "a.b.c", "tav_notatoken", ""} {
			if _, err := v.Verify(context.Background(), raw); err == nil {
				t.Errorf("accepted %q", raw)
			}
		}
	})
}

func TestKeyRotationIsFollowedWithACooldown(t *testing.T) {
	old, rotated := rsaSigner(t, "old"), rsaSigner(t, "new")
	f := newFakeIdP(t, old.public())
	v, now := newVerifier(t, f, oidcConfig())
	base := f.hits()

	// The provider rotates; a token with the new kid arrives.
	f.set(func(f *fakeIdP) { f.keys = []jose.JSONWebKey{rotated.public()} })
	if _, err := v.Verify(context.Background(), rotated.sign(t, goodClaims(), nil)); err == nil {
		t.Fatal("within the cooldown of the startup fetch, no re-fetch is allowed yet")
	}
	*now = now.Add(refetchCooldown)
	if _, err := v.Verify(context.Background(), rotated.sign(t, goodClaims(), nil)); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	if f.hits() != base+1 {
		t.Errorf("fetches = %d, want one more", f.hits()-base)
	}

	// Forged unknown key ids must not make the gateway hammer the provider.
	forger := rsaSigner(t, "nope")
	for range 20 {
		_, _ = v.Verify(context.Background(), forger.sign(t, goodClaims(), nil))
	}
	if f.hits() > base+2 {
		t.Errorf("forged key ids caused %d fetches", f.hits()-base-1)
	}
}

func TestStalenessAndOutages(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, now := newVerifier(t, f, oidcConfig(func(c *config.OIDCConfig) { c.JWKSMaxStaleness = 2 * time.Hour }))

	f.set(func(f *fakeIdP) { f.down = true })
	raw := func() string {
		c := goodClaims()
		c.Expiry = jwt.NewNumericDate(now.Add(time.Hour)) // follows the test clock
		return rs.sign(t, c, nil)
	}

	*now = now.Add(time.Hour)
	if _, err := v.Verify(context.Background(), raw()); err != nil {
		t.Errorf("a provider outage within the staleness bound must not stop validation: %v", err)
	}
	if err := v.refresh(context.Background()); err == nil {
		t.Error("refresh against a down provider must fail")
	}
	if _, err := v.Verify(context.Background(), raw()); err != nil {
		t.Errorf("a failed refresh must keep the cached keys: %v", err)
	}

	*now = now.Add(2 * time.Hour)
	mustReject(t, v, raw(), "staleness")
	if age := v.KeysAge(); age < 3*time.Hour {
		t.Errorf("age = %v", age)
	}

	f.set(func(f *fakeIdP) { f.down = false })
	if err := v.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), raw()); err != nil {
		t.Errorf("recovery: %v", err)
	}
}

func TestNoKeysYet(t *testing.T) {
	v := NewJWTVerifier(oidcConfig(), http.DefaultClient, slog.New(slog.DiscardHandler))
	rs := rsaSigner(t, "rs-1")
	mustReject(t, v, rs.sign(t, goodClaims(), nil), "not available")
	if v.KeysAge() != -1 {
		t.Errorf("age = %v, want -1", v.KeysAge())
	}
}

func TestDiscoveryMustMatchTheIssuer(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	f.set(func(f *fakeIdP) { f.issuerDoc = "https://other.example/realms/x" })
	v := NewJWTVerifier(oidcConfig(), nil, slog.New(slog.DiscardHandler))
	v.http = &http.Client{Transport: rewrite{target: f.srv.URL, rt: http.DefaultTransport}}
	if err := v.refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("refresh = %v, want an issuer mismatch", err)
	}
}

func TestExplicitJWKSURISkipsDiscovery(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig(func(c *config.OIDCConfig) { c.JWKSURI = "http://keys.internal/certs" }))
	if f.discHits != 0 {
		t.Errorf("discovery was used (%d hits) although jwks_uri is set", f.discHits)
	}
	if _, err := v.Verify(context.Background(), rs.sign(t, goodClaims(), nil)); err != nil {
		t.Error(err)
	}
}

func TestOnlyPublicSigningKeysAreAccepted(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	enc := rsaSigner(t, "enc-1")
	enc.key.Use = "enc"
	f := newFakeIdP(t, enc.public(), rs.key /* private: must be ignored */)
	v := NewJWTVerifier(oidcConfig(), nil, slog.New(slog.DiscardHandler))
	v.http = &http.Client{Transport: rewrite{target: f.srv.URL, rt: http.DefaultTransport}}
	if err := v.refresh(context.Background()); err == nil {
		t.Error("a key document without a usable signing key must be refused")
	}
}

func TestRunRefreshesPeriodically(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v := NewJWTVerifier(oidcConfig(func(c *config.OIDCConfig) { c.JWKSRefresh = 20 * time.Millisecond }), nil, slog.New(slog.DiscardHandler))
	v.http = &http.Client{Transport: rewrite{target: f.srv.URL, rt: http.DefaultTransport}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { v.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for f.hits() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if f.hits() < 3 {
		t.Errorf("fetches = %d, want at least 3", f.hits())
	}
}

func TestClaimStrings(t *testing.T) {
	claims := map[string]any{
		"groups":                   []any{"a", "b", 7, ""},
		"scope":                    "openid  profile ai",
		"realm_access":             map[string]any{"roles": []any{"r1", "r2"}},
		"https://x.example/groups": []any{"lit"},
	}
	for path, want := range map[string]string{
		"groups":                   "a,b",
		"scope":                    "openid,profile,ai",
		"realm_access.roles":       "r1,r2",
		"https://x.example/groups": "lit",
		"missing":                  "",
		"realm_access.nope":        "",
		"groups.deeper":            "",
	} {
		if got := strings.Join(claimStrings(claims, path), ","); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

func holderWith(t *testing.T, mappings ...config.OIDCMapping) *config.Holder {
	t.Helper()
	h := &config.Holder{}
	h.Store(&config.Snapshot{OIDC: config.OIDCConfig{Issuer: testIssuer, Mappings: mappings}})
	return h
}

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestOIDCAuthenticatorMapsGroupsToTeamAndModels(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())
	a := OIDCAuthenticator{Verifier: v, Snap: holderWith(t,
		config.OIDCMapping{Group: "ai-research", Team: "research", AllowedModels: []string{"llama-*"}},
		config.OIDCMapping{Group: "ai-vision", Team: "vision", AllowedModels: []string{"llama-*", "vlm"}},
		config.OIDCMapping{Group: "ai-admin", Team: "admin", AllowedModels: []string{"*"}},
	)}

	id, err := a.Authenticate(request(rs.sign(t, goodClaims(), map[string]any{"groups": []string{"ai-vision", "ai-research", "unmapped"}, "azp": "notebook"})))
	if err != nil {
		t.Fatal(err)
	}
	if id.Method != "oidc" || id.Subject != "user-123" || id.KeyID != "" || id.Application != "notebook" {
		t.Errorf("identity = %+v", id)
	}
	// Mapping order, not token order, picks the team; models add up without duplicates.
	if id.Team != "research" || strings.Join(id.AllowedModels, ",") != "llama-*,vlm" {
		t.Errorf("team=%q models=%v", id.Team, id.AllowedModels)
	}
	if !id.CanUseModel("llama-70b") || !id.CanUseModel("vlm") || id.CanUseModel("secret") {
		t.Error("model access does not follow the mappings")
	}

	// Authenticated, but in no mapped group: no team, no model.
	none, err := a.Authenticate(request(rs.sign(t, goodClaims(), map[string]any{"groups": []string{"unmapped"}})))
	if err != nil {
		t.Fatal(err)
	}
	if none.Team != "" || none.CanUseModel("llama-70b") {
		t.Errorf("identity without a mapped group = %+v", none)
	}
}

func TestOIDCAuthenticatorFailuresCarryAReasonButNoToken(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())
	a := OIDCAuthenticator{Verifier: v, Snap: holderWith(t)}

	c := goodClaims()
	c.Expiry = jwt.NewNumericDate(epoch.Add(-time.Hour))
	token := rs.sign(t, c, nil)
	_, err := a.Authenticate(request(token))
	if !isUnauthenticated(err) || Reason(err) != "token expired" {
		t.Errorf("err = %v, reason = %q", err, Reason(err))
	}
	if _, err := a.Authenticate(request("")); !isUnauthenticated(err) {
		t.Errorf("no credential: %v", err)
	}
}

func isUnauthenticated(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), ErrUnauthenticated.Error())
}

func TestChainRoutesByCredential(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())

	key, hash, _ := GenerateKey()
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{
		Keys: map[string]*config.APIKey{hash[len("sha256:"):]: {ID: "svc", Team: "t", Application: "a", AllowedModels: []string{"*"}}},
		OIDC: config.OIDCConfig{Mappings: []config.OIDCMapping{{Group: "g", Team: "research", AllowedModels: []string{"m"}}}},
	})
	chain := Chain{APIKey: APIKeyAuthenticator{Snap: holder}, OIDC: OIDCAuthenticator{Snap: holder, Verifier: v}}

	id, err := chain.Authenticate(request(key))
	if err != nil || id.Method != "api_key" || id.KeyID != "svc" {
		t.Errorf("api key: %+v %v", id, err)
	}
	id, err = chain.Authenticate(request(rs.sign(t, goodClaims(), map[string]any{"groups": []string{"g"}})))
	if err != nil || id.Method != "oidc" || id.Team != "research" {
		t.Errorf("token: %+v %v", id, err)
	}
	if _, err := chain.Authenticate(request("tav_wrong")); Reason(err) != "unknown API key" {
		t.Errorf("a tav_ credential must be judged as an API key, got %v", err)
	}
	if _, err := chain.Authenticate(request("")); !isUnauthenticated(err) {
		t.Errorf("no credential: %v", err)
	}

	// Without OIDC, a token is just an unknown credential.
	apiOnly := Chain{APIKey: APIKeyAuthenticator{Snap: holder}}
	if _, err := apiOnly.Authenticate(request(rs.sign(t, goodClaims(), nil))); !isUnauthenticated(err) {
		t.Errorf("token without OIDC configured: %v", err)
	}
}

func TestOIDCClearanceIsTheHighestOfTheGroups(t *testing.T) {
	rs := rsaSigner(t, "rs-1")
	f := newFakeIdP(t, rs.public())
	v, _ := newVerifier(t, f, oidcConfig())
	a := OIDCAuthenticator{Verifier: v, Snap: holderWith(t,
		config.OIDCMapping{Group: "staff", Team: "t", AllowedModels: []string{"m"}, MaxClassification: config.LabelInternal},
		config.OIDCMapping{Group: "finance", Team: "t", AllowedModels: []string{"m"}, MaxClassification: config.LabelRestricted},
		config.OIDCMapping{Group: "interns", Team: "t", AllowedModels: []string{"m"}, MaxClassification: config.LabelPublic},
	)}
	for groups, want := range map[string]config.Classification{
		"staff,interns":         config.LabelInternal,
		"interns,finance,staff": config.LabelRestricted,
		"interns":               config.LabelPublic,
		"nobody":                config.LabelPublic, // no mapping: no model either
	} {
		id, err := a.Authenticate(request(rs.sign(t, goodClaims(), map[string]any{"groups": strings.Split(groups, ",")})))
		if err != nil {
			t.Fatal(err)
		}
		if id.MaxClassification != want {
			t.Errorf("groups %s: clearance %q, want %q", groups, id.MaxClassification, want)
		}
	}
}

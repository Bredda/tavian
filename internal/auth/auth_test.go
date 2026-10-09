package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/config"
)

func holderWithKey(t *testing.T, key string, models ...string) *config.Holder {
	t.Helper()
	h := &config.Holder{}
	h.Store(&config.Snapshot{Keys: map[string]*config.APIKey{
		HashKey(key): {ID: "dev", Team: "research", Application: "demo", AllowedModels: models},
	}})
	return h
}

func req(authz string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

func TestAuthenticate(t *testing.T) {
	key, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := APIKeyAuthenticator{Snap: holderWithKey(t, key, "llama-*")}

	id, err := a.Authenticate(req("Bearer " + key))
	if err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if id.KeyID != "dev" || id.Team != "research" || id.Method != "api_key" {
		t.Errorf("identity = %+v", id)
	}
	if !id.CanUseModel("llama-70b") || id.CanUseModel("mistral-large") {
		t.Error("model allow-list not applied")
	}

	for name, h := range map[string]string{
		"missing":      "",
		"wrong scheme": "Basic " + key,
		"wrong key":    "Bearer " + key + "x",
		"empty bearer": "Bearer ",
		"no space":     "Bearer" + key,
	} {
		if _, err := a.Authenticate(req(h)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}

	// Case-insensitive scheme per RFC 7235.
	if _, err := a.Authenticate(req("bearer " + key)); err != nil {
		t.Errorf("lowercase scheme rejected: %v", err)
	}
}

func TestAuthenticateWithoutSnapshot(t *testing.T) {
	a := APIKeyAuthenticator{Snap: &config.Holder{}}
	if _, err := a.Authenticate(req("Bearer x")); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("err = %v", err)
	}
}

func TestGenerateKey(t *testing.T) {
	k1, h1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, _, _ := GenerateKey()
	if k1 == k2 {
		t.Error("keys must be unique")
	}
	if !strings.HasPrefix(k1, KeyPrefix) {
		t.Errorf("key %q lacks prefix", k1)
	}
	if h1 != "sha256:"+HashKey(k1) {
		t.Error("config hash must match HashKey")
	}
}

func TestExpiredAPIKeyIsRefused(t *testing.T) {
	key, hash, _ := GenerateKey()
	expiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{Keys: map[string]*config.APIKey{
		hash[len("sha256:"):]: {ID: "svc", Team: "t", Application: "a", AllowedModels: []string{"*"}, ExpiresAt: expiry, MaxClassification: config.LabelConfidential},
	}})
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		return r
	}
	at := func(now time.Time) APIKeyAuthenticator {
		return APIKeyAuthenticator{Snap: holder, Now: func() time.Time { return now }}
	}

	id, err := at(expiry.Add(-time.Second)).Authenticate(req())
	if err != nil {
		t.Fatalf("a key before its expiry must work: %v", err)
	}
	if id.MaxClassification != config.LabelConfidential {
		t.Errorf("clearance = %q", id.MaxClassification)
	}
	// The instant itself is already too late: expires_at is exclusive.
	for _, now := range []time.Time{expiry, expiry.Add(time.Hour)} {
		_, err := at(now).Authenticate(req())
		if !errors.Is(err, ErrUnauthenticated) || Reason(err) != "API key svc expired" {
			t.Errorf("at %v: err = %v, reason %q", now, err, Reason(err))
		}
	}
}

func TestKeyWithoutExpiryNeverExpires(t *testing.T) {
	key, hash, _ := GenerateKey()
	holder := &config.Holder{}
	holder.Store(&config.Snapshot{Keys: map[string]*config.APIKey{hash[len("sha256:"):]: {ID: "svc", AllowedModels: []string{"*"}}}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	far := APIKeyAuthenticator{Snap: holder, Now: func() time.Time { return time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC) }}
	if _, err := far.Authenticate(r); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestAdminTokensAreGeneratedWithTheirOwnPrefix(t *testing.T) {
	token, hash, err := GenerateAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "tavadm_") || strings.HasPrefix(token, KeyPrefix) || hash != "sha256:"+HashKey(token) {
		t.Errorf("token %q hash %q", token, hash)
	}
	other, _, _ := GenerateAdminToken()
	if other == token {
		t.Error("two tokens are the same")
	}
	key, _, _ := GenerateKey()
	if !strings.HasPrefix(key, KeyPrefix) || strings.HasPrefix(key, AdminTokenPrefix) {
		t.Errorf("an API key looks like an admin token: %q", key)
	}
}

func TestAdminAuthenticator(t *testing.T) {
	token, _, _ := GenerateAdminToken()
	key, _, _ := GenerateKey()
	h := &config.Holder{}
	a := AdminAuthenticator{Snap: h}
	if _, err := a.Authenticate(req("Bearer " + token)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("without a snapshot: %v", err)
	}
	h.Store(&config.Snapshot{
		AdminTokens: map[string]*config.AdminToken{HashKey(token): {ID: "ops-alice"}},
		Keys:        map[string]*config.APIKey{HashKey(key): {ID: "app"}},
	})
	who, err := a.Authenticate(req("Bearer " + token))
	if err != nil || who.TokenID != "ops-alice" {
		t.Fatalf("a valid token: %+v %v", who, err)
	}
	for name, authz := range map[string]string{
		"nothing":    "",
		"basic":      "Basic " + token,
		"unknown":    "Bearer tavadm_nope",
		"an API key": "Bearer " + key,
		"the hash":   "Bearer " + HashKey(token),
	} {
		if _, err := a.Authenticate(req(authz)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want unauthenticated", name, err)
		}
	}
	// and the data plane does not take the admin token
	if _, err := (APIKeyAuthenticator{Snap: h}).Authenticate(req("Bearer " + token)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the data plane accepted an admin token: %v", err)
	}
}

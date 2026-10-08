package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"

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

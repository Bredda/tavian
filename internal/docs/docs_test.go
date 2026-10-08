package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func get(t *testing.T, h http.Handler, path string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func handler(enabled *bool) http.Handler {
	mux := http.NewServeMux()
	Register(mux, "1.2.3", func() bool { return *enabled })
	return mux
}

func TestSpecIsValidYAMLWithVersion(t *testing.T) {
	on := true
	rec := get(t, handler(&on), "/openapi.yaml")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc struct {
		OpenAPI string `yaml:"openapi"`
		Info    struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec is not valid YAML: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") || doc.Info.Version != "1.2.3" {
		t.Errorf("openapi=%q version=%q", doc.OpenAPI, doc.Info.Version)
	}
	if strings.Contains(rec.Body.String(), "{{") {
		t.Error("unreplaced placeholder in spec")
	}
	for _, p := range []string{"/v1/models", "/v1/chat/completions"} {
		if doc.Paths[p] == nil {
			t.Errorf("path %s missing from the spec", p)
		}
	}
}

func TestPageAndViewerAreSelfContained(t *testing.T) {
	on := true
	h := handler(&on)

	page := get(t, h, "/docs")
	if page.Code != http.StatusOK || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("/docs: %d %s", page.Code, page.Header().Get("Content-Type"))
	}
	if urls := regexp.MustCompile(`https?://`).FindAllString(page.Body.String(), -1); len(urls) != 0 {
		t.Errorf("page references external resources: %v", urls)
	}
	policy := page.Header().Get("Content-Security-Policy")
	if policy == "" || regexp.MustCompile(`https?:|\*`).MatchString(policy) {
		t.Errorf("CSP must exist and allow no external origin: %q", policy)
	}
	if !strings.Contains(policy, "connect-src 'self'") || !strings.Contains(policy, "default-src 'none'") {
		t.Errorf("CSP = %q", policy)
	}

	js := get(t, h, "/docs/scalar.js")
	if js.Code != http.StatusOK || js.Body.Len() < 1<<20 {
		t.Fatalf("/docs/scalar.js: %d, %d bytes", js.Code, js.Body.Len())
	}
	etag := js.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the viewer")
	}
	if again := get(t, h, "/docs/scalar.js", "If-None-Match", etag); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("conditional request: %d, %d bytes", again.Code, again.Body.Len())
	}
}

func TestDisabledServesNothing(t *testing.T) {
	on := false
	h := handler(&on)
	for _, p := range []string{"/docs", "/docs/scalar.js", "/openapi.yaml"} {
		if rec := get(t, h, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d while disabled, want 404", p, rec.Code)
		}
	}
	on = true // a configuration reload takes effect without a restart
	if rec := get(t, h, "/docs"); rec.Code != http.StatusOK {
		t.Errorf("/docs = %d after enabling", rec.Code)
	}
}

// The vendored bundle must be the one SCALAR.md says it is.
func TestVendoredViewerMatchesItsChecksum(t *testing.T) {
	note, err := os.ReadFile("assets/SCALAR.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`sha256:\s+([0-9a-f]{64})`).FindSubmatch(note)
	if m == nil {
		t.Fatal("no checksum in assets/SCALAR.md")
	}
	sum := sha256.Sum256(viewer)
	if got := hex.EncodeToString(sum[:]); got != string(m[1]) {
		t.Errorf("scalar.js sha256 = %s, SCALAR.md says %s: use scripts/update-scalar.sh", got, m[1])
	}
}

// Package docs serves the API reference: an OpenAPI description of the data
// plane and the Scalar viewer for it. Everything is embedded in the binary, so
// the documentation works in air-gapped deployments, and the page is served
// with a Content-Security-Policy that forbids any request leaving the origin.
package docs

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
)

//go:embed openapi.yaml
var spec string

//go:embed assets/scalar.js
var viewer []byte

// page loads the viewer from our own origin. Fonts are not fetched from the
// Scalar CDN, telemetry and the agent/MCP features are off.
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tavian API</title>
<link rel="icon" href="data:,">
</head>
<body>
<script id="api-reference" data-url="/openapi.yaml" data-configuration='{"withDefaultFonts":false,"telemetry":false,"agent":{"disabled":true},"mcp":{"disabled":true},"hideClientButton":true,"documentDownloadType":"none","showDeveloperTools":"never","hideModels":true}'></script>
<script src="/docs/scalar.js"></script>
</body>
</html>
`

// csp keeps the page, and whatever the viewer does, on its own origin. Scalar
// injects <style> elements and uses data: images and fonts.
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Enabled reports whether the documentation is currently switched on; it is
// asked on every request so a configuration reload takes effect.
type Enabled func() bool

// Register adds GET /docs, /docs/scalar.js and /openapi.yaml to mux.
func Register(mux *http.ServeMux, version string, enabled Enabled) {
	yaml := []byte(strings.ReplaceAll(spec, "{{VERSION}}", version))
	sum := sha256.Sum256(viewer)
	viewerTag := `"` + hex.EncodeToString(sum[:8]) + `"`

	serve := func(contentType string, body []byte, etag string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !enabled() {
				http.NotFound(w, r)
				return
			}
			h := w.Header()
			h.Set("Content-Type", contentType)
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-cache")
			if etag != "" {
				h.Set("ETag", etag)
				if r.Header.Get("If-None-Match") == etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("GET /docs", serve("text/html; charset=utf-8", []byte(page), ""))
	mux.HandleFunc("GET /docs/scalar.js", serve("text/javascript; charset=utf-8", viewer, viewerTag))
	mux.HandleFunc("GET /openapi.yaml", serve("application/yaml; charset=utf-8", yaml, ""))
}

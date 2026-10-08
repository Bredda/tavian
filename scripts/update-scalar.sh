#!/usr/bin/env bash
# Vendor a new version of the Scalar API Reference bundle into internal/docs.
# Usage: scripts/update-scalar.sh 1.73.1
set -euo pipefail

version="${1:?usage: $0 <@scalar/api-reference version>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/internal/docs/assets"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -sSfL -o "$tmp/scalar.js" \
  "https://cdn.jsdelivr.net/npm/@scalar/api-reference@${version}/dist/browser/standalone.js"
sum="$(sha256sum "$tmp/scalar.js" | cut -d' ' -f1)"

install -m 0644 "$tmp/scalar.js" "$dest/scalar.js"
cat > "$dest/SCALAR.md" <<EOT
# Vendored Scalar API Reference

\`scalar.js\` is \`@scalar/api-reference\` (MIT, https://github.com/scalar/scalar),
the \`dist/browser/standalone.js\` bundle, embedded into the binary so the API
documentation works without Internet access.

- version: ${version}
- sha256:  ${sum}

Update with \`scripts/update-scalar.sh <version>\`; never edit the file by hand.
EOT
echo "vendored @scalar/api-reference ${version} (sha256 ${sum})"
echo "Check /docs in a browser (no request may leave the origin), then commit."

#!/usr/bin/env bash
# Run the SDK conformance suite: the official OpenAI Python and Node SDKs
# against a real gateway in front of the mock backend.
#
#   conformance/run.sh            # both SDKs
#   conformance/run.sh python     # or: node
#
# Needs Go, and Python 3 / Node 20+ for the SDKs you run. Dependencies are
# installed into conformance/python/.venv and conformance/node/node_modules.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
which="${1:-all}"

work="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$work/tavian" ./cmd/tavian
go build -o "$work/mockllm" ./cmd/mockllm

"$work/mockllm" -addr 127.0.0.1:18000 >"$work/mockllm.log" 2>&1 &
pids+=($!)
"$work/tavian" serve -config conformance/tavian.yaml >"$work/tavian.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 50); do
  curl -sf http://127.0.0.1:19090/readyz >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf http://127.0.0.1:19090/readyz >/dev/null || { echo "gateway did not become ready:"; cat "$work/tavian.log"; exit 1; }

export TAVIAN_BASE_URL="http://127.0.0.1:18080/v1"
export TAVIAN_KEY="tav_YX9YFmBISettYgGG03tMcKMtUvuGYYZulSPV-sTe5hQ"
export TAVIAN_NARROW_KEY="tav_0hsFppZ-OH4pNXREmkxGWw5xb1tAS_DrCE3JRlTIaKI"

status=0
if [[ "$which" == all || "$which" == python ]]; then
  echo "== Python SDK"
  python3 -m venv conformance/python/.venv
  conformance/python/.venv/bin/pip install -q --disable-pip-version-check -r conformance/python/requirements.txt
  (cd conformance/python && .venv/bin/python -m pytest -q) || status=1
fi
if [[ "$which" == all || "$which" == node ]]; then
  echo "== Node SDK"
  (cd conformance/node && npm ci --silent && npm test) || status=1
fi
[[ $status -eq 0 ]] || { echo "--- gateway log"; cat "$work/tavian.log"; }
exit $status

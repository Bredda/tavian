#!/usr/bin/env bash
# The scenario of docs/VISION.md against the demo stack itself: the real images,
# volumes, read-only file systems and key permissions of deploy/compose (without
# Keycloak, which the scenario does not need).
#
#   scripts/demo-e2e.sh          # builds the images, runs the scenario, tears down
#   KEEP=1 scripts/demo-e2e.sh   # leave the stack running afterwards
#
# The Go test e2e/demo_test.go plays the same scenario against the binaries and
# looks closer at the records; this one checks that what ships works as shipped.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
compose=(docker compose -f deploy/compose/docker-compose.yml)
data=http://127.0.0.1:8080
admin=http://127.0.0.1:9090

# the demo keys are public (README.md)
finance=tav_EV1tUN4aJqmj1nDwAuRd_juZk1MpqqRyuqC9bZ75DK0 # team finance, cleared for confidential
demo=tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI    # cleared for internal only
iban='FR14 2004 1010 0505 0001 3M02 606'

failures=0
pass() { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; failures=$((failures + 1)); }
check() { # check "description" command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

cleanup() {
  status=$?
  if [[ $status -ne 0 || $failures -ne 0 ]]; then
    echo "== gateway logs"; "${compose[@]}" logs --no-color tavian 2>&1 | tail -40 || true
  fi
  if [[ -z "${KEEP:-}" ]]; then "${compose[@]}" down -v >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

psql() { "${compose[@]}" exec -T postgres psql -U tavian -d tavian -Atc "$1"; }

# ask KEY MODEL CONTENT: prints "<http status> <answering backend or error code> <decision id>"
ask() {
  local out
  out="$(curl -s -D - -o /tmp/demo-e2e-body "$data/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$2\",\"max_tokens\":20,\"messages\":[{\"role\":\"user\",\"content\":\"$3\"}]}" | tr -d '\r')"
  local status id who
  status="$(sed -n '1s/^HTTP[^ ]* \([0-9]*\).*/\1/p' <<<"$out")"
  id="$(sed -n 's/^[Xx]-[Tt]avian-[Dd]ecision-[Ii]d: //p' <<<"$out")"
  who="$(grep -o '"x_mock_backend":"[^"]*"' /tmp/demo-e2e-body | head -1 | cut -d'"' -f4 || true)"
  [[ -n "$who" ]] || who="$(grep -o '"code":"[^"]*"' /tmp/demo-e2e-body | head -1 | cut -d'"' -f4 || true)"
  echo "$status $who $id"
}

echo "== starting the demo stack"
"${compose[@]}" up -d --build postgres migrate audit-key tavian mockllm mockllm-external
for _ in $(seq 1 60); do
  curl -sf "$admin/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "$admin/readyz" >/dev/null || { echo "the gateway did not become ready"; exit 1; }
pub="$("${compose[@]}" run --rm audit-key 2>/dev/null | sed -n 's/^public key: //p')"
[[ "$pub" == ed25519:* ]] || { echo "no public key from audit-key"; exit 1; }

echo "== the scenario"
read -r st who id <<<"$(ask $finance demo-shared 'Summarise the quarterly meeting notes')"
[[ "$st $who" == "200 partner-eu" ]] && pass "ordinary data follows the route (external first)" || fail "ordinary data: $st $who"

read -r st who ibanid <<<"$(ask $finance demo-shared "Transfer 100 EUR to $iban")"
[[ "$st $who" == "200 on-prem" ]] && pass "an IBAN is answered by the on-prem model" || fail "IBAN: $st $who"

read -r st who id <<<"$(ask $finance demo-partner "Transfer 100 EUR to $iban")"
[[ "$st $who" == "403 no_eligible_backend" && -n "$id" ]] && pass "the external-only model is refused, with a decision id" || fail "external only: $st $who $id"
[[ "$(psql "select payload->>'reason_code' from outbox where event_id='$id'")" == NO_ELIGIBLE_BACKEND ]] && pass "the refusal record says why" || fail "refusal record"

read -r st who id <<<"$(ask $demo demo-shared "Transfer 100 EUR to $iban")"
[[ "$st $who" == "403 classification_exceeds_clearance" ]] && pass "a caller without the clearance is refused" || fail "clearance: $st $who"

echo "== the audit trail"
sleep 1
rec="$(psql "select payload->>'label' || ' ' || coalesce(payload->'constraints'->>0,'') || ' ' || (payload->>'backend') || ' ' || coalesce(payload->'cost'->>'micro_eur','') from outbox where event_id='$ibanid'")"
[[ "$rec" == confidential\ internal\ mockllm\ * && "$rec" =~ [0-9]$ ]] && pass "the IBAN record: confidential, internal only, on-prem, with a cost ($rec)" || fail "IBAN record: '$rec'"
[[ "$(psql "select count(*) from outbox where kind='decision' and event_id='$ibanid' and payload->'findings' @> '[{\"subtype\":\"iban\"}]'")" == 1 ]] && pass "the record lists the IBAN finding" || fail "IBAN finding"
[[ "$(psql "select count(*) from outbox where kind='usage' and payload->>'cost_micro_eur' is not null and payload->>'energy_wh' is not null and payload->>'co2e_g' is not null")" -ge 1 ]] && pass "usage events carry money, energy and carbon" || fail "usage cost"

# the demo seals the chain every 100 records: make enough of them
echo "  ...   sending 105 requests so that the chain is sealed"
for i in $(seq 1 105); do ask $demo demo-chat "hello $i" >/dev/null; done

verify() { "${compose[@]}" exec -T tavian /app verify-audit -public-key "$pub" "$@"; }
out=""
for _ in $(seq 1 60); do
  out="$(verify 2>&1)" && ! grep -q 'pending:\|no seals yet' <<<"$out" && break
  sleep 1
done
if grep -q 'OK: no problem found' <<<"$out" && grep -q 'signatures verified' <<<"$out" && ! grep -q 'no seals yet' <<<"$out"; then
  pass "verify-audit: the chain and its seals check out"
else
  fail "verify-audit did not come back clean:"; echo "$out"
fi

everything="$( { psql "select payload::text from outbox"; "${compose[@]}" logs --no-color tavian 2>&1; curl -s "$admin/metrics"; } | tr 'a-z' 'A-Z')"
if grep -qF -e '2004 1010' -e '20041010' -e 'FR1420' <<<"$everything"; then fail "the IBAN was found in a record, a log or a metric"; else pass "the IBAN is in no record, log or metric"; fi

psql "update outbox set payload = jsonb_set(payload, '{outcome}', '\"refused\"') where event_id='$ibanid'" >/dev/null
if out="$(verify 2>&1)"; then
  fail "verify-audit accepted a changed record"
elif grep -q 'FAILED' <<<"$out" && grep -q "$ibanid" <<<"$out"; then
  pass "a changed record is found (verify-audit names it and exits non-zero)"
else
  fail "verify-audit failed, but not as expected:"; echo "$out"
fi

echo
if [[ $failures -ne 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "the demo scenario holds"

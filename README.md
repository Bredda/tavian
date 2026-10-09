# Tavian

**Sovereign LLM gateway.** Identity, content security, policy, quotas, metering and audit for LLM access inside organizations that cannot afford to lose control of their data.

> **Status: pre-alpha.** v0.1.0 is the walking skeleton (see [what works today](#what-works-today-v010)): identity, an OpenAI-compatible API and metering run end to end. Content inspection, policy and quotas, which are what the project is about, are designed but not built yet. The design documents below are drafts meant to be challenged.

## What it is

A single entry point between your applications and your LLMs (self-hosted or approved external), exposing an OpenAI-compatible API and enforcing, on every request:

```
Identity → Content inspection → Policy → Routing → Quota → Metering → Audit
```

with one hard constraint: **it must run fully on-prem and air-gapped.** The only outbound traffic ever allowed is from the gateway to explicitly configured, online LLM providers.

## Quick start (demo)

Requires Docker. This starts the gateway, PostgreSQL, Keycloak and a mock OpenAI-compatible backend. The backend sits on a network with no route to the Internet. The first start takes about 30 seconds (Keycloak):

```bash
make demo
curl -s localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI' \
  -H 'Content-Type: application/json' \
  -d '{"model":"demo-chat","messages":[{"role":"user","content":"Bonjour"}]}'
```

Then watch the classification at work. The demo has an on-prem backend and a mock "approved external" provider; the model `demo-shared` is served by both, the external one first. An ordinary prompt goes out, a prompt with an IBAN stays on-prem (the finance key is cleared for `confidential` data, the first key is not and is refused):

```bash
FIN=tav_EV1tUN4aJqmj1nDwAuRd_juZk1MpqqRyuqC9bZ75DK0
ask() { curl -s localhost:8080/v1/chat/completions -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"$3\"}]}" | grep -o '"x_mock_backend":"[^"]*"\|"code":"[^"]*"'; }
ask $FIN demo-shared "Bonjour"                                          # answered by partner-eu
ask $FIN demo-shared "Vire 100 EUR vers FR14 2004 1010 0505 0001 3M02 606"   # answered by on-prem
ask $FIN demo-partner "Vire 100 EUR vers FR14 2004 1010 0505 0001 3M02 606"  # no_eligible_backend
make demo-down
```

The demo also loads policies from `deploy/compose/policies/`: e-mail addresses are replaced by placeholders before they reach a model, secrets are refused, and a third policy runs in *shadow mode* (it enforces nothing, it records what it would have done):

```bash
say() { curl -s localhost:8080/v1/chat/completions -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"$3\"}]}" | grep -o '"content":"[^"]*"\|"message":"[^"]*"'; }
DEMO=tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI
say $DEMO demo-chat "Write to alice@corp.example"      # the model only sees [EMAIL_1]
say $DEMO demo-chat "The key is AKIAIOSFODNN7EXAMPLE"  # blocked by policy (SECRET_IN_PROMPT)
say $DEMO demo-chat "Server 10.12.13.14 is down"       # answered; the shadow policy would have blocked it
docker compose -f deploy/compose/docker-compose.yml exec postgres psql -U tavian -d tavian -c \
  "select payload->>'reason_code' as reason, payload->>'label' as label, payload->'redactions' as redactions, payload->'shadow'->>'would_refuse' as shadow_would_refuse from outbox where kind='decision' order by seq"
```

Every answer carries an `X-Tavian-Decision-Id` header, and the decision record in PostgreSQL (`outbox`, kind `decision`) says why. The keys above are public and for the demo only (`tavian keygen` makes real ones). The interactive API reference (Scalar, with a "Test Request" button) is at <http://localhost:8080/docs>; it is embedded in the binary and works offline. Metrics and health are on `localhost:9090`. An annotated configuration lives in [configs/tavian.example.yaml](configs/tavian.example.yaml); API key expiry, rotation and revocation are in [docs/API_KEYS.md](docs/API_KEYS.md).

### Sign in with OIDC

The demo stack also starts Keycloak (reference identity provider, realm `tavian`). `alice` is in the group `ai-research`, which the demo configuration maps to the team `research` and the `demo-*` models; `bob` is in no group. Passwords equal the user names.

```bash
TOKEN=$(make -s demo-token DEMO_USER=alice)
curl -s localhost:8080/v1/models -H "Authorization: Bearer $TOKEN"   # lists demo-chat
curl -s localhost:8080/v1/models -H "Authorization: Bearer $(make -s demo-token DEMO_USER=bob)"   # empty: authenticated, no access
```

Keycloak takes about 30 seconds to start; the gateway retries fetching its signing keys until it is up. Any OIDC provider works the same way, see the `oidc` section of the example configuration.

## What works today (main, after v0.1.0)

API-key authentication with per-key model allow-lists, or sign-in with any OIDC provider (access tokens, groups mapped to teams and models) · `POST /v1/chat/completions` (streaming included) and `GET /v1/models` · OpenAI-compatible backends (vLLM, …) · strict configuration compiled into an immutable snapshot, reloadable with `SIGHUP` · egress guard enforcing the deployment profile · usage events with token counts, recorded in PostgreSQL (disk spool during outages, requests refused if the audit trail cannot record) · health, readiness and Prometheus metrics · embedded API reference at `/docs`. Content inspection looks for PII (e-mail, IBAN, payment cards, French NIR, phone, IPv4), secrets and your own dictionaries and patterns in everything a request carries, fails closed, and records findings (never the matched text) in the usage event; it observes only for now. Quotas (requests, concurrency and tokens, set in policies) answer 429 with `Retry-After`. Audit evidence is next (M2); see the [roadmap](docs/ROADMAP.md) and [docs/INSPECTION.md](docs/INSPECTION.md).

## Development

`make test`, `make lint`, `make build`. Workflow, commit conventions and releases are described in [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

| Document | Purpose |
|---|---|
| [docs/VISION.md](docs/VISION.md) | Problem, positioning, principles, personas, non-goals |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, deployment profiles, request lifecycle, failure modes |
| [docs/DOMAIN_MODEL.md](docs/DOMAIN_MODEL.md) | Core entities and their relationships |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, content inspection, data classification, egress control, audit |
| [docs/INSPECTION.md](docs/INSPECTION.md) | What is inspected today, detectors, fail-closed behaviour, tuning |
| [docs/POLICY.md](docs/POLICY.md) | Policy model, evaluation semantics, examples, lifecycle |
| [docs/QUOTAS_AND_METERING.md](docs/QUOTAS_AND_METERING.md) | Quotas (reserve/settle), multi-dimensional metering incl. energy and carbon |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Scenario-driven milestones |
| [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md) | Decisions still to make, research still to do |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, trunk-based workflow, commit conventions, releases |
| [docs/adr/](docs/adr/README.md) | Architecture Decision Records |

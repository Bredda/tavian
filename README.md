# Tavian

**Sovereign LLM gateway.** Identity, content security, policy, quotas, metering and audit for LLM access inside organizations that cannot afford to lose control of their data.

> **Status: pre-alpha.** The scenario that defines the project works end to end ([what works today](#what-works-today)): a finance application sends an IBAN, the gateway recognises it, classifies the request `confidential`, keeps it on the on-prem model although an external provider serves the same model name, refuses the external-only model with an explainable reason, counts the quota and the cost in euros, watt-hours and grams of CO₂e, and records a tamper-evident audit trail that `tavian verify-audit` checks. It is tested on every change, against the real binaries and against the demo stack ([`e2e/`](e2e/demo_test.go), [`scripts/demo-e2e.sh`](scripts/demo-e2e.sh)). APIs and configuration may still change; the design documents below are drafts meant to be challenged.

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

Every served request is priced from the prices in the configuration (the demo's are examples), and its energy and carbon are estimated; the cost sits in the decision record and the usage event:

```bash
docker compose -f deploy/compose/docker-compose.yml exec postgres psql -U tavian -d tavian -c \
  "select payload->>'model' as model, payload->>'backend' as backend, payload->>'cost_micro_eur' as micro_eur, payload->>'energy_wh' as wh, payload->>'co2e_g' as g_co2e from outbox where kind='usage' order by seq"
```

Every answer carries an `X-Tavian-Decision-Id` header, and the decision record in PostgreSQL (`outbox`, kind `decision`) says why. The records are also linked into a hash chain, sealed with a signature every 100 records or 5 minutes; check it with the public key of the demo (`docker compose run --rm audit-key` prints it):

```bash
docker compose -f deploy/compose/docker-compose.yml exec tavian /app verify-audit -public-key ed25519:...
```
 The keys above are public and for the demo only (`tavian keygen` makes real ones). To play the same scenario from a GUI, open [bruno/](bruno/) with Bruno (environment `demo-0.2.0`). The interactive API reference (Scalar, with a "Test Request" button) is at <http://localhost:8080/docs>; it is embedded in the binary and works offline. Metrics and health are on `localhost:9090`. An annotated configuration lives in [configs/tavian.example.yaml](configs/tavian.example.yaml); API key expiry, rotation and revocation are in [docs/API_KEYS.md](docs/API_KEYS.md).

### Sign in with OIDC

The demo stack also starts Keycloak (reference identity provider, realm `tavian`). `alice` is in the group `ai-research`, which the demo configuration maps to the team `research` and the `demo-*` models; `bob` is in no group. Passwords equal the user names.

```bash
TOKEN=$(make -s demo-token DEMO_USER=alice)
curl -s localhost:8080/v1/models -H "Authorization: Bearer $TOKEN"   # lists demo-chat
curl -s localhost:8080/v1/models -H "Authorization: Bearer $(make -s demo-token DEMO_USER=bob)"   # empty: authenticated, no access
```

Keycloak takes about 30 seconds to start; the gateway retries fetching its signing keys until it is up. Any OIDC provider works the same way, see the `oidc` section of the example configuration.

## What works today

- **API and identity.** `POST /v1/chat/completions` (streaming included) and `GET /v1/models`, OpenAI-compatible, checked with the official Python and Node SDKs. API keys with per-key model lists and clearances, or sign-in with any OIDC provider (groups mapped to teams, models and clearances).
- **Content inspection** of everything a request carries: PII (e-mail, IBAN, payment cards, French NIR, phone, IPv4), secrets, your own dictionaries and patterns. It fails closed, and findings hold positions and keyed fingerprints, never the matched text ([docs/INSPECTION.md](docs/INSPECTION.md)).
- **Classification and routing.** Each request gets a label (`public` to `restricted`) from what the caller declares, a default and what inspection finds; it must fit the caller's clearance; the router only picks a backend whose destination class and `max_classification` allow it, and a second check asserts the choice before the call.
- **Policies** in YAML with CEL conditions, scoped to the organization, a team or an application, narrowing only: model access, destinations, labels, and actions on findings (`block`, `redact` with verification, `restrict_destinations`, `flag`). A policy can run in shadow mode, and `tavian policy test` runs fixtures through the gateway's own decision code ([docs/POLICY.md](docs/POLICY.md)).
- **Quotas**: requests and tokens per minute, concurrency, tokens per day, and a monthly budget in euros, reserved before the call and settled with real usage; refusals are 429 with `Retry-After` ([docs/QUOTAS_AND_METERING.md](docs/QUOTAS_AND_METERING.md)).
- **Metering**: tokens, cost from the prices you configure, and energy and carbon estimates from profiles and intensities you enter (labelled as estimates), per request and summed by the hour.
- **Audit**: a decision record for every authenticated request, refusals included, with a stable reason code; records are chained and sealed with Ed25519 signatures, and `tavian verify-audit` checks the chain, the seals and copies of seals kept elsewhere ([docs/AUDIT.md](docs/AUDIT.md)). The outbox is pruned by retention without losing that proof.
- **Sovereignty.** An egress guard enforces the deployment profile (air-gapped, controlled-egress, open-egress); configuration is strict and compiled into an immutable snapshot, reloadable with `SIGHUP` or through an administration API (configuration revisions: list, compare, apply, roll back) with its own tokens that records every change in the audit chain ([docs/ADMIN_API.md](docs/ADMIN_API.md)); health, readiness and Prometheus metrics; an embedded API reference at `/docs`; PostgreSQL with a disk spool during outages (requests are refused if the audit trail cannot record).

Not yet: response inspection, a command line for the admin API and an admin UI, model health checks and failover, shared counters for several replicas, encryption of audit content. See the [roadmap](docs/ROADMAP.md).

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
| [docs/AUDIT.md](docs/AUDIT.md) | The tamper-evident audit chain: guarantees, setup, verification |
| [docs/QUOTAS_AND_METERING.md](docs/QUOTAS_AND_METERING.md) | Quotas (reserve/settle), multi-dimensional metering incl. energy and carbon |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What each milestone is for; the work itself is in [issues and milestones](https://github.com/Bredda/tavian/milestones) |
| [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md) | Settled and provisional answers; open questions are [`decision` issues](https://github.com/Bredda/tavian/issues?q=is%3Aissue+label%3Adecision+is%3Aopen) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, trunk-based workflow, commit conventions, releases |
| [docs/adr/](docs/adr/README.md) | Architecture Decision Records |

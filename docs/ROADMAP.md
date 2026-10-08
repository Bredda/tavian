# Roadmap

_Status: draft v0.1_

Milestones are cut by **scenario** (a thing that demonstrably works), not by technical layer. Each ends with a demo. The north star is the finance scenario in [VISION.md](VISION.md#the-demo-that-defines-success).

Security-relevant foundations (config snapshots, decision records, the multi-dimensional usage event, the polymorphic Model target) are laid early even when their features come later, because they are expensive to retrofit.

## M0 — Foundations

- [x] Licence chosen (Apache-2.0), project renamed to Tavian
- [x] Repo skeleton, CI, trunk-based workflow and release-please ([ADR-0013](adr/0013-trunk-based-development-and-release-please.md))
- [x] First ADRs accepted; blocking [open questions](OPEN_QUESTIONS.md) resolved except the pre-publication name checks
- [ ] Create the GitHub repository and run `scripts/setup-github-repo.sh`
- [ ] Short competitive analysis (what exists, where the gap really is)

## M1 — Walking skeleton

> *A developer points the OpenAI SDK at Tavian and talks to a local vLLM, authenticated, with usage recorded.*

- OIDC (generic) + API keys → Identity Context
- `POST /v1/chat/completions` (streaming) and `GET /v1/models`
- One backend type: OpenAI-compatible (covers vLLM)
- PostgreSQL schema + migrations; config loaded into an immutable snapshot
- Usage event with the full multi-dimensional shape (energy/carbon fields present, possibly null)
- Structured content-free logging, `/healthz`, `/metrics`
- Compose file: gateway + PostgreSQL + Keycloak (reference) + vLLM stub

Progress (skeleton merged = ✓):

- [x] Strict config → immutable snapshot, SIGHUP reload keeping the last good revision
- [x] API-key authentication, per-key model allow-list, `tavian keygen`
- [x] `POST /v1/chat/completions` (streaming relayed, usage extracted and forced on streams), `GET /v1/models` (filtered per key)
- [x] OpenAI-compatible backend adapter; client credentials never forwarded upstream
- [x] Egress guard with deployment profiles
- [x] Multi-dimensional `UsageEvent` (money/energy/carbon null for now), emitted to a log sink
- [x] Content-free structured logs, `/healthz`, `/readyz`, `/metrics`
- [x] Compose demo on an Internet-less network (gateway + mock backend)
- [x] PostgreSQL: embedded migrations (`tavian migrate`), usage events via transactional outbox ([ADR-0010](adr/0010-transactional-outbox-no-broker.md)) with a bounded disk spool and fail-closed admission, every config revision persisted
- [ ] Outbox consumers (rollups, export) and retention: events accumulate until they exist
- [x] Generic OIDC bearer validation (JWKS cache with max staleness, group → team/model mappings) behind the `Authenticator` interface
- [x] PostgreSQL in the compose stack
- [x] Keycloak in the compose stack (realm `tavian`, users alice and bob)
- [x] Conformance tests against the OpenAI SDKs (non-streaming, streaming, tool calls): `conformance/`, Python and Node, in CI

## M2 — The finance demo ("prove it")

> *The scenario from VISION.md, end to end.*

- Model catalog, Backends with destination class + max classification, two backends (internal + a mock "external")
- Teams, applications, RBAC roles
- Policy engine: YAML + CEL, default deny, narrowing-only, two-phase evaluation, decision records
- L0 + L1 inspection: PII (IBAN, cards, NIR, email, phone), secrets, custom dictionaries; classification; actions `block/redact/flag/restrict_destinations`
- Egress guard and the three deployment profiles
- Quotas: rpm, concurrency, tpm, tokens/day, budget — reserve/settle, in-memory
- Audit: decision records, content level `hash`, hash chain + `tavian verify-audit`
- Energy/carbon computed from configured profiles
- `tavian policy test` and `shadow` mode

## M3 — Operability

- Admin API + CLI (config as code); read-only auditor role
- Model registry with health checks, multi-backend routing strategies, failover (within constraints)
- `POST /v1/embeddings`
- OpenTelemetry traces (one span per stage), Prometheus metrics, reference Grafana dashboards
- Multi-replica support: Redis shared counters, snapshot distribution
- Usage rollups and chargeback export

## M4 — Security depth

- Response inspection (`observe` → `enforce` with hold-back window)
- L2 local ML detectors (NER, classifier), prompt-injection signals
- Content audit levels `redacted` / `full` with envelope encryption and crypto-shredding
- Signed policy / ruleset bundles for offline distribution; two-person approval for guardrails
- External anchoring of audit seals
- Secret store integrations (Vault, Kubernetes Secrets)
- Anthropic-compatible `/v1/messages`

## M5 — Platform

- Admin UI (policies, usage, audit explorer, "why was this refused?")
- Virtual models: pre/post-processing pipelines and middlewares
- Non-LLM model types: rerankers and other small models
- Energy/carbon quotas and reports, measured energy profiles from local GPU telemetry

## v1.0 — Production grade

- HA (multi-replica gateway, PostgreSQL HA), Kubernetes manifests / Helm chart
- Air-gapped installation bundle (images, models, rulesets, docs) with verification
- Multi-cluster / multi-site with replicated config, disaster-recovery runbooks
- Enterprise policy packs (e.g. GDPR / AI Act / sector-specific starting points)
- Security review, fuzzing, SBOM, signed releases, documented hardening

## Explicitly later / maybe

`POST /v1/responses` · multi-tenancy · multimodal inspection · reversible pseudonymization · response caching with isolation guarantees

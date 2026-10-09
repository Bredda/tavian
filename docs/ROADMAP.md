# Roadmap

_Status: draft v0.1_

Milestones are cut by **scenario** (a thing that demonstrably works), not by technical layer. Each ends with a demo. The north star is the finance scenario in [VISION.md](VISION.md#the-demo-that-defines-success).

Security-relevant foundations (config snapshots, decision records, the multi-dimensional usage event, the polymorphic Model target) are laid early even when their features come later, because they are expensive to retrofit.

## M0 — Foundations

- [x] Licence chosen (Apache-2.0), project renamed to Tavian
- [x] Repo skeleton, CI, trunk-based workflow and release-please ([ADR-0013](adr/0013-trunk-based-development-and-release-please.md))
- [x] First ADRs accepted; blocking [open questions](OPEN_QUESTIONS.md) resolved except the pre-publication name checks
- [x] Create the GitHub repository and run `scripts/setup-github-repo.sh`
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
- [ ] Outbox consumers (rollups, export) and retention: events accumulate until they exist *(scheduled in M2: worker framework with the audit hash chain, then retention and a minimal rollup; chargeback export stays in M3)*
- [x] Generic OIDC bearer validation (JWKS cache with max staleness, group → team/model mappings) behind the `Authenticator` interface
- [x] PostgreSQL in the compose stack
- [x] Keycloak in the compose stack (realm `tavian`, users alice and bob)
- [x] Conformance tests against the OpenAI SDKs (non-streaming, streaming, tool calls): `conformance/`, Python and Node, in CI

_M1 shipped as v0.1.0._

## Before M2 — hardening pass

Gaps found when comparing [SECURITY.md](SECURITY.md) with the code, closed first because M2 builds on them:

- [x] PostgreSQL connections go through the egress guard; a lint rule forbids other direct dialing
- [x] In-flight request cap (`limits.max_inflight`)
- [x] API key lifecycle: `expires_at`, per-key and per-mapping `max_classification` (needed by classification in M2), rotation procedure ([API_KEYS.md](API_KEYS.md))

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

Progress:

- [x] Inspection framework: serializable detector interface, time-boxed engine that fails closed, keyed fingerprints, findings that never hold the matched text, summary in the usage event, metrics ([INSPECTION.md](INSPECTION.md))
- [x] L0 detectors (e-mail, IBAN, payment card, NIR, phone, IPv4, token-shaped secrets, credential assignments) and L1 custom dictionaries and patterns
- [x] Canary test that no content reaches logs, metrics, events or error bodies; fuzz targets for the extractor and detectors; latency benchmark
- [x] Decision records for every authenticated request (refusals included), `decision_id` in the error body and `X-Tavian-Decision-Id`, stable reason codes, kind-aware outbox and spool ([SECURITY.md](SECURITY.md#audit))
- [x] Classification: label from declared header, default and inferred findings, enforced against the caller's clearance, recorded in decision records, usage events and a metric
- [x] Routing by constraints (backend `max_classification` and destination class per label), candidates in the decision record, phase B assertion, named mock backends and an approved-external mock in the demo stack
- [x] Policy engine, part 1: YAML policies in `policy.dir` with CEL conditions, scopes (organization, team, application), narrowing-only models/destinations/default label/label rules, built-in baseline in the same format, policies stored with each revision
- [x] Policy engine, part 2: actions on findings (`block`, `redact` with verification, `restrict_destinations`, `flag`), `label` in action conditions
- [ ] Policy engine, part 3: shadow mode, `tavian policy test`
- [ ] Quotas (reserve/settle, in memory)
- [ ] Outbox worker framework (consumer cursors, runner), hash chain over decision records, `tavian verify-audit`
- [ ] Outbox retention (only sealed segments read by every consumer, seals kept) and a minimal hourly usage rollup, closing the M1 item on consumers and retention
- [ ] Energy, carbon and price snapshot in usage events
- [ ] End-to-end finance demo test in CI

## M3 — Operability

- Admin API + CLI (config as code); read-only auditor role
- Model registry with health checks, multi-backend routing strategies, failover (within constraints)
- `POST /v1/embeddings`
- OpenTelemetry traces (one span per stage), Prometheus metrics, reference Grafana dashboards
- Multi-replica support: Redis shared counters, snapshot distribution
- Usage rollups and chargeback export
- Native TLS on both listeners; mTLS to PostgreSQL and internal backends
- Database-backed API keys with last-use tracking and a revocation list (with the admin API)
- Fuzzing of the request, SSE, JWT and configuration parsers in scheduled CI

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

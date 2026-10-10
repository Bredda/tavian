# Architecture

_Status: draft v0.1 — proposals, not commitments. Decisions are tracked in [adr/](adr/README.md)._

## 1. Constraints that shape everything

1. Must run fully on-prem and air-gapped. Nothing may be fetched from the Internet at runtime or install time (images, models, rulesets, updates are delivered as offline bundles).
2. Must inspect request and response **content** locally.
3. Security decisions fail closed.
4. Operable with minimal moving parts: one binary + PostgreSQL as the baseline.

## 2. Deployment profiles

The profile is a top-level setting, validated at config load **and** enforced at the network dialer.

| Profile | Egress | Backends allowed | Typical use |
|---|---|---|---|
| `air-gapped` | None. The dialer refuses any non-internal destination. | `internal` only | Strictest environments |
| `controlled-egress` | Gateway only, to an explicit allow-list of hosts (optionally via a corporate proxy, custom CA). | `internal`, `approved-external` | Internal models + e.g. a EU-hosted provider |
| `open-egress` | Gateway only, to configured hosts. | `internal`, `approved-external`, `public-external` | Labs, homelabs, non-regulated use |

In every profile, **no component other than the gateway data plane** (IdP, database, dashboards, …) needs or is expected to have outbound access. Reference network policies ship with the deployment manifests.

## 3. Logical components

```
                    OIDC IdP (Keycloak, Entra, …)
                              │  JWKS / discovery (internal)
                              ▼
 AI clients ──────►  ┌──────────────────────────────────────────┐
 (OpenAI SDK, apps)  │            Tavian — data plane           │
                     │                                          │
                     │  authn → admission → authz → inspect →   │ ──► internal backends
                     │  policy → route → quota reserve →        │     (vLLM, llama.cpp, …)
                     │  provider adapter → stream relay →       │
                     │  quota settle → events                   │ ──► approved / public external
                     │                                          │     (through the egress guard)
                     └───────▲───────────────────────┬──────────┘
                             │ config snapshot       │ events (transactional outbox)
                     ┌───────┴──────────┐     ┌──────▼───────┐
                     │  Control plane   │────►│  PostgreSQL  │  source of truth
                     │  admin API / CLI │     └──────────────┘
                     │  (UI later)      │
                     └──────────────────┘

 Optional, added when scale requires it:  Redis (shared counters) · OTel collector · Grafana · Prometheus
```

### Data plane
Stateless-ish request path. Holds an immutable in-memory **config snapshot** (models, backends, policies, quotas, API key hashes, rulesets). Never queries PostgreSQL to serve a request.

### Control plane
Admin API and its command line (`tavian config`; a UI later), described in [ADMIN_API.md](ADMIN_API.md). Validates and versions configuration, produces a new snapshot revision, publishes it; today it lists, compares, validates, applies and rolls back configuration revisions, reloads the configuration file, and lists the changes made. In the baseline it lives in the same binary as the data plane, behind a separate listener and separate authentication; the boundary is a package boundary now and can become a process boundary later ([ADR-0003](adr/0003-config-snapshots-and-plane-separation.md)).

### Egress guard
The only code path that opens outbound connections: to model backends, to the identity provider and to PostgreSQL. It resolves destinations against the configured endpoints and the active profile, and refuses anything else; internal endpoints (every one under `air-gapped`, and the database always) must resolve to internal addresses, checked on every resolved address. A lint rule keeps other packages from dialing ([ADR-0008](adr/0008-single-egress-point-and-deployment-profiles.md)).

*Implemented in v0.1.0:* the allow-list, profile enforcement, internal-address checks, no redirects, no proxy from the environment. *Planned:* DNS pinning, TLS enforcement with a custom CA bundle, an explicit outbound HTTP proxy, reference network policies.

### Inspection engine
In-process pipeline of local detectors producing *findings* and a *classification label*. See [SECURITY.md](SECURITY.md#content-inspection).

### Events
Usage events and audit records are written to an **outbox table in PostgreSQL** in the same transaction domain as the decision log, then consumed by workers (hash-chain sealing and hourly usage sums are built; export comes next). Consumers keep a cursor in PostgreSQL that moves in the same transaction as their effects, run on one instance at a time, and read rows in the order of the transactions that wrote them (`internal/outbox`, [ADR-0010](adr/0010-transactional-outbox-no-broker.md)); the audit chain is described in [AUDIT.md](AUDIT.md). No message broker in the baseline ([ADR-0010](adr/0010-transactional-outbox-no-broker.md)).

## 4. Request lifecycle

```
 1  receive          assign request_id / trace_id, size and header limits
 2  authenticate     JWT (OIDC) or API key → Identity Context (user, groups, team, app)
 3  admission        cheap checks first → protects the expensive steps below
                    (in-flight cap `limits.max_inflight`; rpm and concurrency per scope, taken
                    before the body is read; built)
 4  authorize        RBAC: may this principal call this API and this model alias?
 5  normalize        parse into an internal request representation (messages, tools, params)
 6  inspect (req)    detectors → findings; then the classification label (built)
 7  policy (phase A) inputs: identity, model, label, findings → constraints:
                       allowed destination classes (built; the label must fit the caller's
                       clearance), required transforms (redact) and rules: with the policy engine
 8  transform        apply redactions if required
 9  route            model alias → candidate backends, filtered by constraints (built:
                       first allowed target of the route); health, capabilities,
                       context window and strategies: M3
10  policy (phase B) assertion: chosen backend satisfies constraints (defence in depth, built)
11  quota reserve    TPM / tokens-per-day / budget reservation using estimated usage and the chosen backend's price (built)
12  call provider    through the egress guard (internal backends use the same dialer path)
13  relay response   stream pass-through; response inspection per policy (see below)
14  quota settle     replace the reservation with actual usage (refund the difference; built)
15  emit events      usage event + audit record via outbox (async consumers)
```

Notes:

- **Admission before inspection** (step 3) prevents inspection CPU from becoming a DoS vector.
- **Quota reservation after routing** (step 11) because cost depends on the chosen backend's price.
- **Failover never widens constraints.** If the preferred backend fails, only other candidates that already passed the constraint filter are eligible.
- Steps 4–10 produce a **decision record** (findings, chosen backend, reason code; rules matched and constraints arrive with the policy engine) even for refused requests. It exists from the moment the caller is authenticated: a request refused earlier (bad credentials, overload) leaves metrics and logs only, because recording unauthenticated traffic would let anyone fill the audit trail. One more exception, for the same reason: quota refusals (429) are recorded at most once a second per caller and limit, with the number of refusals the record stands for; the others are counted in metrics and carry no `decision_id`.

### Streaming

Responses are relayed token by token. Response inspection has three modes, set per policy:

| Mode | Behavior | Trade-off |
|---|---|---|
| `off` | No response inspection | Fastest |
| `observe` | Inspect asynchronously; findings are recorded, nothing is blocked | No added latency, no prevention |
| `enforce` | Hold back a small sliding window (N tokens/chars) before releasing it to the client; on a finding, terminate the stream with an error event | Adds a bounded delay; cannot "un-send" what already left the window |

Usage is extracted from the final chunk when the provider supplies it, otherwise counted locally.

### Failure modes

| Failure | Behavior |
|---|---|
| IdP / JWKS unreachable | Keep validating with cached keys up to a configurable max staleness; unknown `kid` → reject |
| PostgreSQL unavailable | Data plane keeps serving from its snapshot; events spool to a bounded local disk queue; spool full → **reject** (audit cannot be guaranteed) |
| Inspection error or timeout | **Block** (`inspection_failed`). A per-detector `on_error: allow` is planned with the policy engine; today there is no such exception |
| New config snapshot invalid | Keep last known good snapshot, raise an alert |
| Quota store unavailable | Default **fail closed**; optional degraded mode with conservative local limits |
| Backend fails before first byte | Fail over within the allowed candidate set |
| Backend fails mid-stream | Terminate with an error event, no retry, settle partial usage |
| Client disconnects | Cancel upstream, settle partial usage |
| Audit spool full | Reject new requests (policies may relax this for non-audited traffic only) |

## 5. API surface

Compatibility with existing SDKs is a primary adoption driver.

| Phase | Endpoints |
|---|---|
| First | `POST /v1/chat/completions` (incl. streaming, tool calls), `GET /v1/models` |
| Next | `POST /v1/embeddings` |
| Later | Anthropic-compatible `POST /v1/messages`, `POST /v1/rerank`, `POST /v1/responses` (stateful, costly to do right) |

Rules:

- The gateway **never fetches URLs found in prompts** (e.g. `image_url`). Multimodal parts are blocked or passed through by explicit policy; an inspection gap is declared, not hidden.
- Error bodies follow the OpenAI error shape, extended with a stable `code` and, for authenticated callers, a `decision_id` (also in the `X-Tavian-Decision-Id` response header) that names the decision record explaining the answer. They never echo detected sensitive values.
- `GET /v1/models` returns only what the caller is authorized to use.

## 6. Observability

- **Tracing:** OpenTelemetry. One span per stage (`auth`, `admission`, `inspect`, `policy`, `route`, `quota`, `provider`). Attributes: `request_id`, `user_id`, `team_id`, `app_id`, `model`, `backend`, `decision`. **Never** prompt content.
- **Metrics:** Prometheus, bounded cardinality (no user id as a label by default).
- **Logs:** structured, content-free.
- Telemetry exporters point at *internal* collectors only; the air-gapped profile refuses non-internal exporter endpoints.

## 7. Persistence

PostgreSQL is the source of truth for configuration, usage aggregates and audit. Hot counters (RPM, concurrency, rolling TPM) live in process memory in a single-instance deployment and move to Redis when running multiple replicas ([QUOTAS_AND_METERING.md](QUOTAS_AND_METERING.md#state-and-scaling)).

## 8. Proposed technology (open to challenge)

| Concern | Choice | Why |
|---|---|---|
| Language | Go | Static single binary, strong net/http + streaming story, easy air-gapped delivery |
| HTTP | `net/http` | Fewer dependencies, full control of streaming |
| DB access | `pgx` + `sqlc`, versioned migrations | Typed queries, no ORM magic |
| Policy conditions | CEL (`cel-go`) | Safe, non-Turing-complete, fast ([ADR-0006](adr/0006-policy-yaml-with-cel.md)) |
| Regex | Go `regexp` (RE2) | Linear time: no ReDoS on attacker-controlled prompts |
| Telemetry | OpenTelemetry SDK, Prometheus client | Standards |

Package layout (✓ = present in the M1 skeleton, the rest are placeholders with a `doc.go` or planned):

```
cmd/tavian/                ✓ entrypoint: serve, validate, migrate, policy test, keygen, version (later: verify-audit)
cmd/mockllm/               ✓ fake OpenAI-compatible backend for demos and tests
internal/config/           ✓ strict YAML → validated, immutable Snapshot; profile rules; Holder
internal/auth/             ✓ API keys and OIDC access tokens (JWKS cache) → Identity
internal/egress/           ✓ the only outbound dialer: allow-list + internal-address enforcement
internal/router/           ✓ model → backend (first target allowed by the constraints; strategies and health later)
internal/provider/openai/  ✓ OpenAI-compatible adapter: streaming relay + usage extraction
internal/meter/            ✓ multi-dimensional UsageEvent + sinks: PostgreSQL outbox with disk spool, log sink (dev)
internal/server/           ✓ data-plane and admin HTTP handlers, middleware, Prometheus metrics
internal/docs/             ✓ embedded OpenAPI description + Scalar viewer served at /docs (offline, strict CSP)
internal/mockllm/          ✓ mock backend implementation
internal/glob, ids, version  ✓ small utilities
internal/inspect/          ✓ detectors, findings, fail-closed engine (classification: M2)
internal/policy/           ✓ YAML + CEL evaluation, baseline policy, scopes, actions on findings, shadow mode
internal/pipeline/         ✓ the decision steps (model authorization, policy, clearance, routing, phase B) shared by the gateway and `policy test`
internal/quota/            ✓ admission, reserve/settle, in-memory counters, refusal coalescing (shared counters: M3)
internal/cost/             ✓ prices, energy profiles, carbon: cost of a request
internal/audit/            ✓ decision records and reason codes (encryption: M4)
internal/outbox/           ✓ consumers of the outbox: cursors, one runner per consumer, xid horizon; the pruner (retention)
internal/rollup/           ✓ hourly usage sums (usage_hourly) and the rebuild of daily token counters
internal/chain/            ✓ audit hash chain, signed seals, verification (`tavian verify-audit`)
internal/admin/            ✓ control-plane API: tokens, change records, reload (docs/ADMIN_API.md)
internal/store/            ✓ PostgreSQL access (pgx): embedded migrations, outbox, config revisions
internal/spool/            ✓ bounded on-disk queue for events while PostgreSQL is down
```

## 9. Scaling path

1. **Single instance** — one binary, PostgreSQL, in-memory counters. Enough for most small and medium deployments.
2. **Multiple replicas** — shared counters in Redis (or PostgreSQL if throughput allows); snapshot distribution via PostgreSQL polling/notify.
3. **HA / multi-cluster** — Kubernetes, PostgreSQL HA, per-site gateways with a replicated config, disaster-recovery runbooks, offline update bundles.

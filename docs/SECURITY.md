# Security

_Status: draft v0.1_

Content security is what makes the "sovereign" claim real: knowing *who* called is not enough, the gateway must control *what data goes where*.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Prompts and responses | May contain personal, confidential or regulated data |
| Provider credentials | Let an attacker spend money or exfiltrate through a provider |
| API keys and tokens | Impersonation |
| Policy and configuration | Defines what is allowed; tampering silently weakens everything |
| Audit trail | The evidence; must be trustworthy even against admins |

Trust boundaries: client ↔ gateway · gateway ↔ IdP · gateway ↔ PostgreSQL · gateway ↔ backend (internal / external) · admin ↔ control plane.

## Threats and mitigations

| # | Threat | Mitigations |
|---|---|---|
| T1 | Careless user pastes sensitive data into a prompt | Request inspection, classification, policy-driven redact/block/restrict destinations |
| T2 | Sensitive data routed to an unapproved provider | Backend destination class + max classification; routing filters on constraints; failover never widens; phase-B assertion |
| T3 | Compromised application / stolen API key | Hashed, scoped, expirable keys; app max classification; quotas bound the blast radius; anomaly metrics |
| T4 | Prompt injection causing data exfiltration through tools/URLs | Never fetch URLs from prompts; injection signal detectors; tool-call content inspection; response inspection `enforce` |
| T5 | Malicious model output (leaked secrets, harmful content) | Response inspection per policy |
| T6 | Insider admin weakens policy or alters evidence | Separated roles; every config change is a versioned, audited `ConfigRevision`; hash-chained audit with external anchoring; policy changes can require two-person approval |
| T7 | Compromised external provider / network attacker | Egress allow-list; only data allowed by policy is ever sent; TLS with pinned CA bundle option (planned) |
| T8 | Data exfiltration from the gateway itself | Egress guard; no telemetry; network policies deny all other egress; air-gapped profile refuses non-internal dialing |
| T9 | DoS via expensive requests (huge prompts, ReDoS) | Size limits, admission control before inspection, RE2 regex (linear time), per-detector time budgets |
| T10 | SSRF via prompt content or configuration | Gateway never dereferences URLs from requests; backend endpoints come only from validated config |
| T11 | Cross-user leakage | No response caching; no shared mutable context across requests; strict per-request memory scope |
| T12 | Content leaking through observability | Content never in logs, traces or metric labels; lint/test to enforce; findings store no raw values |
| T13 | Supply chain (dependencies, rulesets, models) | Reproducible builds, SBOM, signed release artifacts and signed offline ruleset/policy bundles, minimal dependencies |

## Content inspection

*In main after v0.1.0:* the framework, the L0 detectors listed in [INSPECTION.md](INSPECTION.md), custom dictionaries and patterns, and fail-closed handling are built. They **observe only**: findings are recorded in the usage event and nothing acts on them yet; classification and actions come with the policy engine. L2/L3 below are planned.

### Principles

- **Local only.** Detectors never call an external service. A detector that needs a model ships the model in the offline bundle.
- **Layered by cost.** Cheap deterministic detectors run on every request; expensive ones are opt-in per policy.
- **Pluggable.** A detector is an interface (`Inspect(content) → findings`), implemented in-process (L0/L1) or as a local sidecar over a Unix socket / loopback gRPC (L2+).
- **Time-boxed.** Each detector has a budget; exceeding it is an error, and errors fail closed by default.

### Layers

| Layer | Detectors | Cost | Phase |
|---|---|---|---|
| **L0 — deterministic** | Scanners with validators: email, phone, IBAN (mod-97), card numbers (Luhn), French NIR (checksum), IPv4; secrets (cloud keys, tokens, private keys, JWT, credential assignments). *Planned: IPv6 and host names, other countries' national IDs, high-entropy strings* | µs–ms | MVP (built) |
| **L1 — configurable** | Customer dictionaries and patterns (project code names, client lists, document markings like "CONFIDENTIEL") | ms | MVP (built) |
| **L2 — local ML** | NER for names/addresses/organizations; text classifier for data classes; prompt-injection classifier. Small models, CPU-friendly, run in an optional local sidecar ([ADR-0012](adr/0012-ml-detectors-as-local-sidecar.md)) | 10s of ms | Later |
| **L3 — LLM-as-judge** | An *internal* model reviewing ambiguous cases. Async or slow path only | 100s of ms+ | Optional |

### Findings

```
Finding {
  detector     string        // "pii.fr.iban"
  type         enum          // pii | secret | classification | injection | custom
  subtype      string        // iban, nir, aws_access_key, …
  severity     enum          // low | medium | high | critical
  confidence   float
  location     { segment, message_index, field, part, start, end }   // offsets in the normalized text; field from a fixed vocabulary
  fingerprint  string        // HMAC-SHA256(key, subtype || value), 128 bits; never the value
}
```

The matched text is not stored in findings. Fingerprints use a keyed hash so identical values can be correlated without being recoverable. Usage events carry only a summary (counts per type, detector versions); locations and fingerprints are for decision records.

### Actions

*In main after v0.1.0:* policies map findings to actions as described in [POLICY.md](POLICY.md#actions-on-findings): `block`, `restrict_destinations`, `redact` (with verification of the result), `flag` and `allow`. Policy maps findings and conditions to actions:

`allow` · `flag` (record only) · `redact` (replace with typed placeholders such as `[IBAN_1]`) · `restrict_destinations` · `block`.

Reversible pseudonymization (restoring original values in the response) is attractive but introduces a mapping store holding sensitive data. It is deferred ([OPEN_QUESTIONS](OPEN_QUESTIONS.md)).

### Request-side vs response-side

- **Request:** synchronous and complete before anything leaves the gateway. This is the strong guarantee. Every string of the body is inspected, known field or not; a request that cannot be inspected completely (detector failure, budget exceeded, non-text part, too many strings) is refused.
- **Response:** see streaming modes in [ARCHITECTURE.md](ARCHITECTURE.md#streaming). `enforce` can only protect what has not yet left the hold-back window.
- **Tool calls and function arguments** are content and are inspected like messages.
- **Multimodal parts** (images, audio, files, unknown types) cannot be inspected: such requests are refused (`multimodal_not_inspectable`). An explicit `pass_through` flagged in the decision record is planned with the policy engine.

## Data classification

Ordered labels (default `public < internal < confidential < restricted`). The **effective label** of a request is the *maximum* of:

1. the **declared** label (header or application setting, bounded by the application's max classification),
2. the **team/policy default** label,
3. the **inferred** label from findings (mapping from finding types/severities to labels, e.g. IBAN → `confidential`).

A caller can only raise the label, never lower it below what inspection infers.

*In main after v0.1.0:* the label is computed for every authenticated chat request and recorded in the decision record with its three sources (and in the usage event and the `tavian_requests_by_label_total` metric).
- **Declared:** the `X-Tavian-Classification` request header (`public`, `internal`, `confidential` or `restricted`; anything else is a 400). A declaration below what inspection infers, or below the default, changes nothing.
- **Default:** `internal`, raised by any policy that sets a higher `classification.default` for the caller's scope ([POLICY.md](POLICY.md)).
- **Inferred**, by the rules of the built-in baseline policy (to which your policies add): any secret → `restricted`; IBAN, payment card, French NIR → `confidential`. E-mail, phone, IP address and custom detectors do not raise the label on their own (the default `internal` already keeps them off public destinations). Your own policies add rules, for example to give a label to a custom dictionary. The inference uses every kind of finding seen, even when the detailed findings were cut at the per-request cap.
- **Clearance:** a request whose label is above the caller's clearance (`max_classification` of the key or the person's groups, [API_KEYS.md](API_KEYS.md#clearance-max_classification)) is refused with 403 `classification_exceeds_clearance`, never silently lowered. The message names the label, never the content.

**Routing enforces the label.** The policy turns the label into constraints: which destination classes may receive it. The built-in baseline policy sets the table below; policies for a team or an application can only remove entries from it:

| Label | Destination classes allowed |
|---|---|
| `public` | internal, approved-external, public-external |
| `internal` | internal, approved-external |
| `confidential` | internal |
| `restricted` | internal |

Routing walks the targets of the requested model in order and takes the first backend that satisfies **both** its own `max_classification` (default: `restricted` for internal backends, `internal` for approved-external, `public` for public-external) **and** the table above. A model served by an external provider and by the on-prem backend therefore goes to the external one for ordinary data and to the on-prem one for an IBAN, even though the external one comes first. If no target is eligible the request is refused with 403 `no_eligible_backend`; the message names the label, never the content. The decision record lists the backends considered, in order, with why each one before the chosen one was set aside (`BACKEND_CLASSIFICATION_TOO_LOW`, `DESTINATION_CLASS_NOT_ALLOWED`).

**Phase B.** After routing, an independent check recomputes the constraints from the label and the policies and asserts that the chosen backend satisfies them. A failure means a routing bug: the request is refused with 500 (`ROUTING_ASSERTION_FAILED`, recorded) rather than sent. Failover (M3) will only consider candidates that already passed the filter.

Backends declare `destination_class` and `max_classification`. A request may only be routed to a Backend with `max_classification ≥ label` whose destination class the policy allows for that label. Classification is thus enforced by *routing*, not by hoping each rule is written correctly.

## Egress control

*In v0.1.0:* single egress guard (backends, identity provider, PostgreSQL), allow-list, deployment profiles, internal-address enforcement, lint rule against other dialing. Everything marked "planned" below is not built yet.

- The gateway is the only component with outbound access, via a single egress guard. That covers model backends, the identity provider and PostgreSQL: the database connection is made with the guard's dialer and, whatever the profile, may only reach an internal address (unix sockets are refused). A lint rule (`forbidigo`) fails the build if any other package dials, resolves names or uses a ready-made HTTP client.
- Outbound destinations are derived only from validated configuration (backends, the identity provider) and the database URL chosen by the operator, never from request content; the active deployment profile gates which destination classes may exist.
- In `air-gapped`, configuration containing a non-internal Backend is rejected at load, and the dialer refuses non-internal addresses even if one slipped through.
- Planned: optional outbound proxy and custom CA bundle for corporate networks, and reference Kubernetes `NetworkPolicy` and firewall rules shipped with the deployment manifests, so that the guarantee does not depend on the application alone. Until then, enforce the same boundary with your own firewall or network policies.
- No telemetry, update checks or licence checks. Ever.

## Audit

### What is recorded

Always, for every request (including refused ones): the `DecisionRecord` — identity, config revision, requested/served model and backend, label, finding summaries (no values), rules matched, outcome, reason codes, usage and cost.

*In main after v0.1.0:* a decision record is written for every **authenticated** chat request, refused ones included, in the PostgreSQL outbox (kind `decision`, with the same disk spool and fail-closed behaviour as usage events). It holds identity, config revision, requested model, chosen backend, outcome, a stable reason code, and the inspection summary and findings (positions and keyed fingerprints, never values). The label, rules matched and constraints are added by the policy engine, usage and cost stay in the usage event, which carries the `decision_id`. A refusal is recorded **before** the answer is sent, so the `decision_id` a caller receives (`X-Tavian-Decision-Id` header, `error.decision_id`) always exists; if the record cannot be stored the request fails with `audit_unavailable`. Requests refused before the caller is known (bad credentials, overload) are only counted and logged: recording them would let anyone fill the audit trail. The same reasoning applies to a caller who keeps hitting a quota: a 429 is recorded (with the limit, its usage and the number of refusals it stands for) at most once a second per caller and limit, and the others carry no `decision_id`; otherwise one misbehaving key could fill the spool and put the whole gateway in fail-closed.

| Outcome | Reason codes |
|---|---|
| `served` | `SERVED` (a `shadow` section may say what policies in shadow mode would have changed) |
| `refused` | `INVALID_REQUEST`, `REQUEST_TOO_LARGE`, `MODEL_NOT_ALLOWED`, `CLEARANCE_EXCEEDED`, `MODEL_NOT_FOUND`, `NO_ELIGIBLE_BACKEND`, `ROUTING_ASSERTION_FAILED`, `POLICY_ERROR`, `POLICY_BLOCKED` (or the `reason` of the block rule), `REDACTION_INCOMPLETE`, `REDACTION_FAILED`, `MULTIMODAL_NOT_INSPECTABLE`, `REQUEST_TOO_COMPLEX`, `INSPECTION_FAILED`, `UPSTREAM_UNAVAILABLE` |
| `failed` | `UPSTREAM_ERROR` (the backend answered with an error status), `STREAM_INTERRUPTED`, `CLIENT_DISCONNECTED` |

Reason codes are stable; the OpenAI-compatible error `code` that SDKs see (`model_not_allowed`, …) is unchanged. Spooled records that cannot be read back are set aside in `events.rejected` and counted (`tavian_spool_rejected_records_total`), never dropped. The hash chain over these records is described below and in [AUDIT.md](AUDIT.md).

Optionally, per policy, the **content** at one of four levels:

| Level | Stored |
|---|---|
| `none` | No content |
| `hash` | Hash of the content only (proves *what* was sent if the original is later presented) |
| `redacted` | Content after redaction |
| `full` | Full prompt/response, encrypted |

Default: `hash`. Storing content is a conscious, policy-level decision with a mandatory retention period.

### Integrity

- Audit records are append-only and linked by a **hash chain** (each entry commits to the record and to the previous entry), built by an outbox consumer. *Built; see [AUDIT.md](AUDIT.md).*
- The chain is periodically **sealed and signed** (Ed25519, key outside the database); seals can be exported to an independent location (offline media, a separate system) so that tampering by someone with database access is detectable. *Built.*
- `tavian verify-audit` recomputes the chain and verifies signatures and exported seals. Auditors need only a read-only database role, which `tavian audit-role` prints the SQL for (select on the audit tables and nothing else; a test tries to write, delete, truncate, drop and alter with it), and `tavian audit-export` writes the chain with its records as JSON lines ([AUDIT.md](AUDIT.md#for-the-auditor)). *Built.*
- Retention removes old events from the outbox, decision records only once a signed seal covers them; every removal is logged so that `verify-audit` can tell retention from tampering ([AUDIT.md](AUDIT.md#retention)). *Built.*
- Not yet: a signing key in a KMS or HSM, automatic export of seals.

### Confidentiality and erasure

- Content is encrypted with **envelope encryption**: a data key per record (or small batch), wrapped by a master key from a file, an HSM/KMS, or Vault.
- The hash chain covers metadata and ciphertext. Deleting a record's data key (**crypto-shredding**) satisfies erasure and retention expiry **without breaking the chain**.

## Secrets management

- Provider credentials are never in the policy/config store in plaintext: Backends reference a secret (file mounted by the platform, Kubernetes Secret, Vault). A built-in encrypted store may exist for the small-deployment path.
- API keys: shown once (`tavian keygen`), stored only as a SHA-256 hash, never in clear. Keys are 256-bit random values, so there is nothing to brute-force and a salt would add nothing: the hash is only a lookup handle. The `tav_` prefix marks the secret's type for secret scanners; the key's identity is its configured `id`, which is what usage events carry.
- Key lifecycle ([API_KEYS.md](API_KEYS.md)): *revoke* by removing the entry and reloading (`SIGHUP`, effective on the next request); *rotate* by adding the new key next to the old one, moving clients over, then removing the old one, with no downtime; *expire* with `expires_at` (refused from that instant, named in the logs, counted in metrics). Each key and each OIDC group mapping carries a `max_classification` clearance, enforced against the label of every request ([data classification](#data-classification)). Database-backed keys with last-use tracking come with the admin API (M3).
- OIDC access tokens are verified locally and cannot be revoked before they expire: keep their lifetime short at the identity provider ([ADR-0002](adr/0002-generic-oidc.md)).
- Administration API: its own tokens (`tavadm_`, `tavian keygen -admin`), stored as SHA-256 like API keys, in `admin.tokens` with an id that names the author of every change and a role (admin, operator or auditor, [ADR-0016](adr/0016-admin-roles.md)) that limits what the token may do; they can expire (`expires_at`, named in the logs and counted in metrics), be rotated and revoked without a restart, and the last use of each is visible without a write per request; the data plane's keys and tokens are not accepted there and the reverse ([ADMIN_API.md](ADMIN_API.md)). Sign-in through OIDC with MFA enforced at the IdP is planned.

## Limits and residual risk

We state these plainly rather than hide them:

- Content inspection is **best-effort**. No detector set catches everything; paraphrased, encoded or obfuscated data can evade deterministic detectors, and ML detectors have error rates.
- Response `enforce` mode cannot recall content already released.
- Multimodal and file content are not inspected, so requests carrying them are refused. Object keys in the request body are not inspected either.
- A user can still memorize and retype data that the gateway never sees; the gateway controls only what passes through it.
- TLS is not terminated by Tavian yet: run it behind a TLS-terminating proxy or service mesh, and keep the admin listener on a private interface. Native TLS on both listeners comes in M3. (PostgreSQL connections can already use TLS through the connection URL, `sslmode=verify-full`.)
- A compromised gateway host defeats the gateway; hardening, signed builds and host isolation remain the operator's responsibility.
- Energy and carbon figures are estimates.

## Hardening checklist

Status on main after v0.1.0. Items are meant to become tests.

- [x] Run as non-root, read-only filesystem, no capabilities (image and compose file)
- [x] Separate listeners/ports for data plane and admin, with separate credentials; every administrative change is recorded before it is made and chained ([ADMIN_API.md](ADMIN_API.md))
- [ ] TLS everywhere; mTLS to PostgreSQL and internal backends where possible. *Database TLS works through the URL; native listener TLS and backend mTLS: M3*
- [x] Request size, header, and concurrency limits (`limits.max_request_bytes`, header timeout, `limits.max_inflight`)
- [x] CI check that no code path logs request/response bodies: a canary test sends sensitive values down the answered, streamed, backend-error, refused and inspection-failure paths and checks the logs (debug level), metrics, usage events and error bodies. *No lint rule yet; the response path is covered once response inspection exists*
- [x] CI check that outbound connections only originate from the egress guard (`forbidigo` rule; PostgreSQL goes through the guard too)
- [ ] Fuzzing for the request parser and detectors. *Done for the content extractor and the detectors (`make fuzz`, seed corpora run in `go test`); the SSE, JWT and configuration parsers and scheduled runs: M3*
- [x] Dependency updates (Dependabot for Go modules, Actions, Docker, and the conformance suite's SDK pins)
- [ ] SBOM, signed releases. *Release archives carry checksums today; signing and SBOM are v1.0, see [#68](https://github.com/Bredda/tavian/issues/68) and [#91](https://github.com/Bredda/tavian/issues/91))*

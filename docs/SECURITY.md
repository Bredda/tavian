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
| T7 | Compromised external provider / network attacker | TLS with pinned CA bundle option; egress allow-list; only data allowed by policy is ever sent |
| T8 | Data exfiltration from the gateway itself | Egress guard; no telemetry; network policies deny all other egress; air-gapped profile refuses non-internal dialing |
| T9 | DoS via expensive requests (huge prompts, ReDoS) | Size limits, admission control before inspection, RE2 regex (linear time), per-detector time budgets |
| T10 | SSRF via prompt content or configuration | Gateway never dereferences URLs from requests; backend endpoints come only from validated config |
| T11 | Cross-user leakage | No response caching; no shared mutable context across requests; strict per-request memory scope |
| T12 | Content leaking through observability | Content never in logs, traces or metric labels; lint/test to enforce; findings store no raw values |
| T13 | Supply chain (dependencies, rulesets, models) | Reproducible builds, SBOM, signed release artifacts and signed offline ruleset/policy bundles, minimal dependencies |

## Content inspection

### Principles

- **Local only.** Detectors never call an external service. A detector that needs a model ships the model in the offline bundle.
- **Layered by cost.** Cheap deterministic detectors run on every request; expensive ones are opt-in per policy.
- **Pluggable.** A detector is an interface (`Inspect(content) → findings`), implemented in-process (L0/L1) or as a local sidecar over a Unix socket / loopback gRPC (L2+).
- **Time-boxed.** Each detector has a budget; exceeding it is an error, and errors fail closed by default.

### Layers

| Layer | Detectors | Cost | Phase |
|---|---|---|---|
| **L0 — deterministic** | Regex + validators: email, phone, IBAN (mod-97), card numbers (Luhn), national IDs (e.g. French NIR checksum), IP/hostnames; secrets (cloud keys, tokens, private keys, high-entropy strings) | µs–ms | MVP |
| **L1 — configurable** | Customer dictionaries and patterns (project code names, client lists, document markings like "CONFIDENTIEL") | ms | MVP |
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
  location     { message_index, start, end }
  fingerprint  string        // keyed hash of the value, for dedup/correlation; never the value
}
```

The matched text is not stored in findings. Fingerprints use a keyed hash so identical values can be correlated without being recoverable.

### Actions

Policy maps findings and conditions to actions (see [POLICY.md](POLICY.md)):

`allow` · `flag` (record only) · `redact` (replace with typed placeholders such as `[IBAN_1]`) · `restrict_destinations` · `block`.

Reversible pseudonymization (restoring original values in the response) is attractive but introduces a mapping store holding sensitive data. It is deferred ([OPEN_QUESTIONS](OPEN_QUESTIONS.md)).

### Request-side vs response-side

- **Request:** synchronous and complete before anything leaves the gateway. This is the strong guarantee.
- **Response:** see streaming modes in [ARCHITECTURE.md](ARCHITECTURE.md#streaming). `enforce` can only protect what has not yet left the hold-back window.
- **Tool calls and function arguments** are content and are inspected like messages.
- **Multimodal parts** (images, audio, files) cannot be inspected in early versions; policy must choose `block` or an explicit `pass_through` flagged in the decision record.

## Data classification

Ordered labels (default `public < internal < confidential < restricted`). The **effective label** of a request is the *maximum* of:

1. the **declared** label (header or application setting, bounded by the application's max classification),
2. the **team/policy default** label,
3. the **inferred** label from findings (mapping from finding types/severities to labels, e.g. IBAN → `confidential`).

A caller can only raise the label, never lower it below what inspection infers.

Backends declare `destination_class` and `max_classification`. A request may only be routed to a Backend with `max_classification ≥ label` whose destination class the policy allows for that label. Classification is thus enforced by *routing*, not by hoping each rule is written correctly.

## Egress control

- The gateway is the only component with outbound access, via a single egress guard. That covers model backends, the identity provider and PostgreSQL: the database connection is made with the guard's dialer and, whatever the profile, may only reach an internal address (unix sockets are refused). A lint rule (`forbidigo`) fails the build if any other package dials, resolves names or uses a ready-made HTTP client.
- Outbound destinations are derived only from validated Backend configuration; the active deployment profile gates which destination classes may exist.
- In `air-gapped`, configuration containing a non-internal Backend is rejected at load, and the dialer refuses non-internal addresses even if one slipped through.
- Optional outbound proxy and custom CA bundle for corporate networks.
- Reference Kubernetes `NetworkPolicy` and firewall rules ship with the deployment manifests so the guarantee does not depend on the application alone.
- No telemetry, update checks or licence checks. Ever.

## Audit

### What is recorded

Always, for every request (including refused ones): the `DecisionRecord` — identity, config revision, requested/served model and backend, label, finding summaries (no values), rules matched, outcome, reason codes, usage and cost.

Optionally, per policy, the **content** at one of four levels:

| Level | Stored |
|---|---|
| `none` | No content |
| `hash` | Hash of the content only (proves *what* was sent if the original is later presented) |
| `redacted` | Content after redaction |
| `full` | Full prompt/response, encrypted |

Default: `hash`. Storing content is a conscious, policy-level decision with a mandatory retention period.

### Integrity

- Audit records are append-only and linked by a **hash chain** (each record includes the hash of the previous one) per chain segment.
- Segments are periodically **sealed and signed**; seals can be exported to an independent location (offline media, a separate system) so that tampering by someone with database access is detectable.
- `tavian verify-audit` recomputes the chain and verifies signatures. Auditors get a read-only role.

### Confidentiality and erasure

- Content is encrypted with **envelope encryption**: a data key per record (or small batch), wrapped by a master key from a file, an HSM/KMS, or Vault.
- The hash chain covers metadata and ciphertext. Deleting a record's data key (**crypto-shredding**) satisfies erasure and retention expiry **without breaking the chain**.

## Secrets management

- Provider credentials are never in the policy/config store in plaintext: Backends reference a secret (file mounted by the platform, Kubernetes Secret, Vault). A built-in encrypted store may exist for the small-deployment path.
- API keys: shown once (`tavian keygen`), stored only as a SHA-256 hash, never in clear. Keys are 256-bit random values, so there is nothing to brute-force and a salt would add nothing: the hash is only a lookup handle. The `tav_` prefix marks the secret's type for secret scanners; the key's identity is its configured `id`, which is what usage events carry.
- Key lifecycle: *revoke* by removing the entry and reloading (`SIGHUP`, effective on the next request); *rotate* by adding the new key next to the old one, moving clients over, then removing the old one, with no downtime. Expiry (`expires_at`) and a per-key maximum classification are planned before M2; database-backed keys with last-use tracking come with the admin API (M3).
- OIDC access tokens are verified locally and cannot be revoked before they expire: keep their lifetime short at the identity provider ([ADR-0002](adr/0002-generic-oidc.md)).
- Admin API uses OIDC with MFA enforced at the IdP.

## Limits and residual risk

We state these plainly rather than hide them:

- Content inspection is **best-effort**. No detector set catches everything; paraphrased, encoded or obfuscated data can evade deterministic detectors, and ML detectors have error rates.
- Response `enforce` mode cannot recall content already released.
- Multimodal and file content are not inspected in early versions.
- A user can still memorize and retype data that the gateway never sees; the gateway controls only what passes through it.
- TLS is not terminated by Tavian yet: run it behind a TLS-terminating proxy or service mesh, and keep the admin listener on a private interface. Native TLS on both listeners comes in M3. (PostgreSQL connections can already use TLS through the connection URL, `sslmode=verify-full`.)
- A compromised gateway host defeats the gateway; hardening, signed builds and host isolation remain the operator's responsibility.
- Energy and carbon figures are estimates.

## Hardening checklist

Status as of v0.1.0. Items are meant to become tests.

- [x] Run as non-root, read-only filesystem, no capabilities (image and compose file)
- [x] Separate listeners/ports for data plane and admin
- [ ] TLS everywhere; mTLS to PostgreSQL and internal backends where possible. *Database TLS works through the URL; native listener TLS and backend mTLS: M3*
- [ ] Request size, header, and concurrency limits. *Size and header limits done; an in-flight cap is next*
- [ ] CI check that no code path logs request/response bodies. *Planned with content inspection (M2): a canary test across success, error and stream paths, plus lint*
- [x] CI check that outbound connections only originate from the egress guard (`forbidigo` rule; PostgreSQL goes through the guard too)
- [ ] Fuzzing for the request parser and detectors. *Detectors with content inspection (M2); parsers right after*
- [x] Dependency updates (Dependabot for Go modules, Actions, Docker, and the conformance suite's SDK pins)
- [ ] SBOM, signed releases. *Release archives carry checksums today; signing and SBOM are v1.0 (see [OPEN_QUESTIONS](OPEN_QUESTIONS.md) 21)*

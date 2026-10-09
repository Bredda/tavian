# Roadmap

_Status: draft v0.2_

Milestones are cut by **scenario** (a thing that demonstrably works), not by technical layer. Each ends with a demo. The north star is the finance scenario in [VISION.md](VISION.md#the-demo-that-defines-success).

Security-relevant foundations (config snapshots, decision records, the multi-dimensional usage event, the polymorphic Model target) are laid early even when their features come later, because they are expensive to retrofit.

**This page says what each milestone is for. What is left to do, what is in progress and what has been decided lives on GitHub**, so that there is one place to look:

- [Issues and milestones](https://github.com/Bredda/tavian/milestones): one milestone per milestone below, main issues (`epic`) with their sub-issues, `decision` issues for open questions.
- [Project board](https://github.com/users/Bredda/projects/7): status, priority and size.
- [Releases](https://github.com/Bredda/tavian/releases) and the [changelog](../CHANGELOG.md): what shipped.
- [Architecture decision records](adr/README.md): what was decided and why.

## Delivered

### M0 — Foundations

Licence (Apache-2.0), the name Tavian, repository skeleton, CI, trunk-based development and release-please ([ADR-0013](adr/0013-trunk-based-development-and-release-please.md)), the first ADRs.

### M1 — Walking skeleton (v0.1.0)

*A developer points the OpenAI SDK at Tavian and talks to a local vLLM, authenticated, with usage recorded.* Identity (API keys and generic OIDC), the OpenAI-compatible API with streaming, an immutable configuration snapshot with `SIGHUP` reload, the egress guard and deployment profiles, PostgreSQL with a transactional outbox and a disk spool, content-free logs and metrics, SDK conformance tests, and a compose demo on a network without Internet.

A short hardening pass followed: PostgreSQL connections through the egress guard, an in-flight request cap, API key expiry and per-key clearances ([API_KEYS.md](API_KEYS.md)).

### M2 — The finance demo, "prove it" (v0.2.0)

*The scenario from VISION.md, end to end*, now a test that runs on every change (`e2e/`, `scripts/demo-e2e.sh`). It delivered:

- content inspection (PII, secrets, your own dictionaries; fail closed) and classification of every request against the caller's clearance ([INSPECTION.md](INSPECTION.md));
- routing by constraints (backend destination class and maximum classification), asserted again before the call;
- the policy engine (YAML + CEL, narrowing scopes, actions on findings, shadow mode, `tavian policy test`) ([POLICY.md](POLICY.md));
- quotas (requests, concurrency, tokens, monthly budget) reserved and settled in memory ([QUOTAS_AND_METERING.md](QUOTAS_AND_METERING.md));
- prices, energy and carbon estimates in the usage events and decision records;
- decision records for every authenticated request, a hash chain with signed seals, `tavian verify-audit`, outbox retention and hourly usage sums ([AUDIT.md](AUDIT.md)).

## Next

### M3 — Operability

*Run it in production.* An admin API and CLI (configuration as code, database-backed API keys, a read-only auditor role); a model registry with health checks, routing strategies and failover that never widens a constraint; `POST /v1/embeddings`; OpenTelemetry traces, dashboards and alerts; several replicas (shared quota counters, snapshot distribution); a chargeback export; native TLS and mTLS; scheduled fuzzing; operator runbooks.

### M4 — Security depth

Response inspection (`observe`, then `enforce` with a hold-back window); local ML detectors and prompt-injection signals; content audit levels with envelope encryption and crypto-shredding; signed policy bundles and two-person approval; external anchoring of audit seals and keys in a KMS; secret store integrations; an Anthropic-compatible `/v1/messages`.

### M5 — Platform

An admin UI (policies, usage, audit explorer, "why was this refused?"); virtual models (pipelines on a single request); non-LLM model types; energy and carbon quotas and measured energy profiles.

### v1.0 — Production grade

High availability and Kubernetes manifests, an air-gapped installation bundle, multi-site, enterprise policy packs, signed releases with an SBOM, a security review.

### Later, maybe

`POST /v1/responses` · multi-tenancy · multimodal inspection · reversible pseudonymization · response caching with isolation guarantees. Each is waiting for a decision or for demand, see the `Later` milestone.

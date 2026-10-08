# Open questions

_Status: living document. Items marked **[blocking]** should be settled before M1._

## Product and project

1. ~~**Licence.**~~ **Resolved 2026-10-08:** Apache-2.0 ([ADR-0011](adr/0011-apache-2-licence.md)).
2. **[blocking, overdue] Name and namespace.** *The repository is public and v0.1.0 is released, so these checks should happen now rather than "before the first public release".* The original working name "GAIIA" collided with an existing company, gaiia (ISP billing/OSS-BSS software, Québec, funded, positioned on AI), and "Veyra" collided with several AI-agent projects, so the project was renamed **Tavian** (2026-10-08). A web search found no direct collision in the AI/gateway/security space (only an unrelated developer handle, `tavianator`), and Tavian is phonetically close to Tavily (an LLM search API). Web search is not authoritative: **before the first public release**, check the GitHub org/repo, domains (`tavian.io`, `.dev`, `.eu`), INPI/EUIPO/USPTO trademark registers and package registries (npm, PyPI, crates.io, Go modules).
3. **Competitive analysis.** Study existing LLM gateways (open source and commercial) and enterprise API gateways with AI plugins. Verify that the combination *air-gapped + content-aware routing by classification + audit evidence + environmental cost* is genuinely unoccupied, and identify what to learn from or integrate with rather than rebuild.
4. **Governance and contribution model.** Solo project for now; define when it matters (CONTRIBUTING, DCO/CLA, security disclosure process).

## Architecture

5. ~~**Small-deployment path.**~~ **Resolved 2026-10-08:** PostgreSQL only, no SQLite mode; compensate with an excellent compose quick start ([ADR-0001](adr/0001-single-binary-postgres-baseline.md)).
6. ~~**ML detectors runtime.**~~ **Resolved 2026-10-08:** local sidecar, optional, over a local socket ([ADR-0012](adr/0012-ml-detectors-as-local-sidecar.md)). The detector interface defined in M2 must therefore be remote-friendly (serializable request/response, deadlines, batching).
7. **Multi-tenancy.** One organization per deployment now. Do we need hard tenant isolation later (shared infra, separate data and keys)? If yes, tenant id must be threaded through the model early.
8. **Snapshot distribution** for multi-replica: PostgreSQL `LISTEN/NOTIFY` + polling vs a pull endpoint. Prefer the simplest that tolerates partitions.
9. **Quota store failure.** Confirm fail-closed default vs degraded local limits as the documented default.
10. **Tokenizers.** Which tokenizers to embed for input estimation across model families, and how to stay conservative for unknown ones.

## Security

11. **Multimodal and files.** Block by default? Pass-through with explicit policy? OCR/image inspection is out of scope early; confirm the declared-gap approach.
12. **Reversible pseudonymization.** Valuable for utility (redact, call model, restore) but the mapping store becomes a sensitive asset. Worth the complexity, and when?
13. **Admin separation of duties.** How strict for the first release: simple roles, or full two-person approval and external audit anchoring from the start?
14. **Erasure vs tamper-evidence.** Crypto-shredding design needs a legal sanity check (GDPR erasure, retention obligations) with real use cases.
15. **Client-declared classification.** How far to trust a header from an application? Currently bounded by the application's max classification; is that enough?
16. **Streaming `enforce` UX.** Hold-back window size vs latency vs protection; what do SDKs do with a mid-stream error event?

## Metering and environment

17. **Energy data sources.** Which public benchmarks or methodologies to base default Wh/token profiles on, with what disclosed uncertainty. How to ingest local GPU power telemetry in an air-gapped setup.
18. **Carbon accounting scope.** Operational electricity only, or also embodied/amortized hardware? Start with operational only and say so.

## API

19. **`/v1/responses`.** Stateful API; implement, translate to chat completions, or decline? Defer until real demand.
20. **Compatibility surface.** How far do we go in mimicking provider-specific quirks (tool-call formats, JSON mode, logprobs)? Define a conformance test suite instead of case-by-case fixes.

## Release engineering

21. **Supply-chain evidence for releases.** Container image signing (cosign keyless vs key-based, which is awkward air-gapped), SBOM generation, SLSA provenance, reproducible builds. Air-gapped consumers need to verify signatures offline against a published public key.
22. **GoReleaser.** The release workflow builds archives with plain `go build` to stay small and auditable; switch to GoReleaser if packaging (deb/rpm, Homebrew) becomes a need.
23. **DCO / CLA.** Currently none; decide before accepting external contributions ([ADR-0011](adr/0011-apache-2-licence.md)).
24. **Go version policy.** `go.mod` targets the previous stable release (1.26) while CI/Docker track it; define how many releases back we support.

## Regulatory context to review (not legal advice)

GDPR (data minimization, erasure, DPIA), EU AI Act (logging and transparency duties by risk class), NIS2, and French/EU qualification schemes for sovereign cloud (e.g. SecNumCloud). Goal: make sure the audit and data-handling design can *support* these obligations; not to claim compliance.

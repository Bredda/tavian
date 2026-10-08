# ADR-0004: Content inspection happens in the gateway, locally

- Status: Proposed
- Date: 2026-10-08

## Context
A sovereign gateway that only sees identity and metadata cannot stop sensitive data from reaching an unapproved destination. Inspection requires reading prompts and responses. Calling an external DLP service would contradict the air-gapped constraint.

## Decision
- The gateway reads and inspects request and response content in-process through a pluggable **detector** interface producing findings and a classification label.
- Detectors are strictly local; models and rulesets ship in offline bundles.
- Layered by cost (L0 deterministic → L3 internal LLM judge); the MVP ships L0 and L1.
- Content never appears in logs, traces or metrics. Stored content is a separate, explicit, encrypted, policy-controlled audit option.

## Consequences
- The gateway becomes a high-value target holding sensitive data in memory; hardening and strict memory scoping are required.
- Latency budget must be managed (admission control before inspection, per-detector time boxes).
- Streaming responses make enforcement harder; modes `off/observe/enforce` expose the trade-off.
- Inspection is best-effort and the residual risk is documented.

## Alternatives considered
- Metadata-only gateway — cannot enforce data-dependent routing.
- External DLP appliance via ICAP/API — possible as an *internal* detector adapter later, but not the baseline.

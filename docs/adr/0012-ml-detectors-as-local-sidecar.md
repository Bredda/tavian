# ADR-0012: ML detectors run as an optional local sidecar

- Status: Accepted (2026-10-08)
- Date: 2026-10-08

## Context
L2 detectors (NER, classification, prompt-injection signals) need ML runtimes. Embedding them in the Go process (ONNX via cgo) would enlarge the binary, complicate cross-compilation and reproducible builds, and place a large native dependency inside the process that holds decrypted prompts. L0/L1 detectors are pure Go and need none of this.

## Decision
- L0/L1 detectors run in-process.
- L2+ detectors run in a **separate, optional local sidecar** reached over a Unix domain socket or loopback gRPC, with no network egress of its own.
- The detector interface is defined from M2 as **remote-friendly**: serializable request/findings, per-call deadline, batching, explicit health and version reporting.
- Models and rulesets for the sidecar are delivered in signed offline bundles.
- A sidecar error or timeout follows the fail-closed rule (ADR-0005) unless the detector is explicitly configured `on_error: allow`.

## Consequences
- The gateway binary stays static; deployments without ML pay nothing.
- One more component to deploy, supervise and patch when L2 is enabled; packaged in the compose/Helm deliverables.
- Sidecar compromise exposes the content it processes: it must run with the same isolation as the gateway (non-root, read-only filesystem, no network).
- The sidecar implementation language is free (e.g. Python or Rust) and can evolve independently.

## Alternatives considered
- In-process ONNX (cgo) — lower latency, single binary, but the downsides above.
- Deferring the decision — rejected because the interface shape in M2 depends on it.

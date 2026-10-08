# ADR-0005: Security decisions fail closed

- Status: Proposed
- Date: 2026-10-08

## Context
Distributed components fail. For a governance product, silently continuing without enforcement or evidence defeats its purpose.

## Decision
When the gateway cannot establish that a request is allowed, it refuses it:

- authentication/authorization uncertainty → reject;
- inspection error or timeout → block (opt-out only per non-critical detector via explicit `on_error: allow`);
- policy cannot be evaluated → reject;
- audit spool full → reject audited traffic;
- quota store unavailable → reject by default, with an optional documented degraded mode.

Availability measures (snapshots, local spooling, failover within allowed backends) exist to reduce how often this happens, never to bypass it.

## Consequences
- Operators must monitor and size the system; outages of dependencies are visible to users.
- Clear error codes are needed to distinguish "refused by policy" from "refused because the control path is degraded".
- Every opt-out is explicit configuration and is recorded in the decision record.

## Alternatives considered
- Fail open — unacceptable for the target audience.
- Per-component defaults hidden in code — rejected; behavior must be documented and testable.

# ADR-0003: Data plane serves from config snapshots; control plane is a separate boundary

- Status: Accepted (2026-10-08), implemented in M1
- Date: 2026-10-08

## Context
Policies, models, backends, quotas and keys are read on every request. Querying PostgreSQL on the hot path adds latency and makes availability depend on the database. We also need to know exactly which configuration produced each decision.

## Decision
- All configuration is compiled into an **immutable, numbered `ConfigRevision` snapshot** held in memory by the data plane.
- The control plane validates changes and publishes new revisions; the data plane swaps atomically and keeps the last known good snapshot if a new one is invalid.
- Every `DecisionRecord` references its revision.
- Control plane and data plane share a binary initially but have separate packages, listeners and authentication, so they can be split into processes without redesign.

## Consequences
- The data plane keeps serving during a PostgreSQL outage (except where audit cannot be guaranteed — see ADR-0005).
- Config propagation is eventually consistent across replicas; revisions make this observable.
- Revocation latency (e.g. a revoked API key) is bounded by snapshot refresh; a short-path invalidation mechanism may be needed for revocations.
- Large catalogs increase memory use; acceptable at expected scale.

## Alternatives considered
- Per-request DB lookups with a cache — implicit staleness, no clean revision identity.
- A dedicated config service — extra component, contradicts ADR-0001.

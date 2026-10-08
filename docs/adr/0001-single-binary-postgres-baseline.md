# ADR-0001: Single Go binary with PostgreSQL as the only mandatory dependency

- Status: Accepted (2026-10-08) — PostgreSQL only, no embedded SQLite mode
- Date: 2026-10-08

## Context
The original sketch lists Keycloak, PostgreSQL, Redis, NATS, MinIO and Grafana. In air-gapped environments every extra component must be packaged, approved, patched and operated offline. It also raises the bar for the secondary audience (small teams, homelabs).

## Decision
The baseline deployment is **one Go binary + PostgreSQL**. The IdP is external to Tavian (required for OIDC but not part of it). Redis, object storage, Prometheus/Grafana and an OTel collector are optional and introduced only by the scaling path (see ARCHITECTURE.md §9). The binary contains data plane, control plane and workers, started by sub-command or flag.

## Consequences
- Fast path to a first running instance; simple air-gapped delivery.
- Some capabilities (shared counters across replicas) require adding Redis later; the quota interface must abstract the counter store from the start.
- Control plane and data plane live in one process initially; package boundaries must be respected (see ADR-0003).
- ML detectors run in an optional sidecar so the binary stays static (see ADR-0012).
- The small-team path relies on a very good compose quick start rather than a second storage engine.

## Alternatives considered
- Microservices from day one — operational cost with no benefit at this scale.
- Embedded SQLite for tiny deployments — rejected: second storage backend to test and migrate.

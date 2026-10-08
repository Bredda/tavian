# ADR-0010: Transactional outbox instead of a message broker

- Status: Accepted (2026-10-08), implemented in M1
- Date: 2026-10-08

## Context
Usage and audit events must be reliably delivered to analytics, audit sealing and export. The sketch proposed NATS. A broker is another component to run offline, and a dual write (DB + broker) risks losing or duplicating events.

## Decision
Events are written to an **outbox table in PostgreSQL**. In-process workers consume them (aggregation, hash-chain sealing, export) with at-least-once semantics and idempotent handlers keyed by event id. If PostgreSQL is briefly unavailable, events spool to a bounded local disk queue and are flushed on recovery; if the spool fills, audited requests are rejected (ADR-0005).

## Consequences
- No extra infrastructure; events and decisions share transactional guarantees.
- Throughput is bounded by PostgreSQL; acceptable for expected load, with batching.
- A broker (NATS) can be introduced later behind the same event interface if fan-out or throughput demands it.

## Alternatives considered
- NATS/Kafka from the start — more moving parts, dual-write problem.
- Direct synchronous writes only — couples request latency to DB, no replay.

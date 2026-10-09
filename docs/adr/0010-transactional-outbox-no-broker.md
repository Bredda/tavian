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

## Implementation notes (2026-10)
- `outbox.seq` is assigned when a row is inserted, not when its transaction commits, so a consumer cannot simply read "everything after the last seq". Rows carry the id of the inserting transaction (`xid8`); a consumer reads, in `(xid, seq)` order, only rows whose xid is below the oldest transaction still running (`pg_snapshot_xmin`). Every older transaction has finished by then, so no row can appear behind a cursor. The cost is latency: a long transaction anywhere in the cluster delays consumers while it runs. An advisory lock at insertion (so that seq follows commit order) was rejected: it would serialise every writer.
- A consumer's cursor lives in `outbox_consumers` and moves in the same transaction as the consumer's effects; a transaction-scoped advisory lock keeps one instance per consumer.

## Alternatives considered
- NATS/Kafka from the start — more moving parts, dual-write problem.
- Direct synchronous writes only — couples request latency to DB, no replay.

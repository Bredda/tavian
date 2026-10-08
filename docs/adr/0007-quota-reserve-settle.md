# ADR-0007: Quotas use reserve/settle accounting

- Status: Proposed
- Date: 2026-10-08

## Context
Token usage and cost are only known after a response, which may be streamed or cut. Pure post-hoc counting lets concurrent requests overshoot limits; pure pre-estimation misbills.

## Decision
- Cheap admission checks (RPM, concurrency) run first.
- After routing, the gateway **reserves** an estimate (input estimate + capped output) against TPM/day/budget quotas using the selected backend's price.
- After the call it **settles** with actual usage, keyed by `request_id` for idempotency; stale reservations expire by TTL and are reconciled.
- The counter store sits behind an interface: in-memory for one instance, Redis for several.

## Consequences
- Limits are honest under concurrency; estimates must err high.
- Needs tokenizer support and a default output cap policy.
- Added complexity in crash recovery (TTL + reconciliation from usage events).

## Alternatives considered
- Post-hoc only — overshoot under load.
- Strict pre-billing at max tokens — over-conservative, blocks legitimate use.

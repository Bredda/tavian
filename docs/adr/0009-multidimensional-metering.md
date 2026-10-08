# ADR-0009: Multi-dimensional metering including energy and carbon

- Status: Proposed
- Date: 2026-10-08

## Context
Environmental cost should be as visible as monetary cost. Retrofitting a dimension into historical usage data is impossible; recording it early is cheap.

## Decision
Every `UsageEvent` carries tokens (in/out/cached/reasoning), cost € (from a price snapshot), energy Wh, carbon gCO₂e, and latency. Energy comes from a per-backend `EnergyProfile` with an explicit `method` (`measured`/`benchmark`/`estimated`) and confidence; carbon applies a configurable, versioned grid intensity per site. All figures are labelled as estimates. Energy and carbon can be targets of quotas like any other dimension.

## Consequences
- Schema is richer from M1, even if energy fields are null at first.
- We must document the methodology and its uncertainty, and avoid false precision.
- Operators supply carbon intensity; no external data fetch (air-gapped).

## Alternatives considered
- Add environmental metrics later — loses history, forces a schema migration on a hot, large table.
- Cost-only metering — misses a differentiating capability.

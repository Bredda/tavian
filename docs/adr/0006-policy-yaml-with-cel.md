# ADR-0006: Policy as declarative YAML with CEL conditions

- Status: Proposed
- Date: 2026-10-08

## Context
Policies must be readable by security officers, reviewable in Git, testable, and evaluated cheaply per request. A custom DSL is costly to design and document; a full policy language (Rego) is powerful but heavy and harder to bound.

## Decision
Policies are YAML documents (`apiVersion`/`kind`/`spec`). Static structure (allow/deny lists, destinations by classification, quotas) is plain YAML. Conditional logic uses **CEL** expressions in `when:` fields. Scopes (org → team → app → user) only narrow; default deny; most restrictive action wins.

## Consequences
- Non-Turing-complete, side-effect-free, type-checkable at load time, bounded evaluation cost.
- Contributors need to learn CEL basics; documentation and fixtures must carry that.
- We own the schema and its versioning (`tavian/v1alpha1` → stable).
- A future adapter to OPA/Rego remains possible behind the same decision interface if demand appears.

## Alternatives considered
- OPA/Rego — expressive, mature, but larger runtime surface and steeper learning curve.
- Cedar — attractive for authorization, less natural for data-inspection conditions.
- Custom DSL — rejected as a known trap.

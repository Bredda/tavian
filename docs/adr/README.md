# Architecture Decision Records

Each ADR captures one significant decision: context, decision, consequences. Status is one of `Proposed` · `Accepted` · `Superseded by ADR-XXXX` · `Rejected`. An ADR is never rewritten after acceptance; it is superseded by a new one.

| # | Title | Status |
|---|---|---|
| [0001](0001-single-binary-postgres-baseline.md) | Single Go binary with PostgreSQL as the only mandatory dependency | Accepted |
| [0002](0002-generic-oidc.md) | Generic OIDC for identity; Keycloak as reference | Accepted |
| [0003](0003-config-snapshots-and-plane-separation.md) | Data plane serves from config snapshots; control plane is a separate boundary | Accepted |
| [0004](0004-in-gateway-content-inspection.md) | Content inspection happens in the gateway, locally | Proposed |
| [0005](0005-fail-closed.md) | Security decisions fail closed | Proposed |
| [0006](0006-policy-yaml-with-cel.md) | Policy as declarative YAML with CEL conditions | Proposed |
| [0007](0007-quota-reserve-settle.md) | Quotas use reserve/settle accounting | Proposed |
| [0008](0008-single-egress-point-and-deployment-profiles.md) | Gateway is the single egress point; deployment profiles | Accepted |
| [0009](0009-multidimensional-metering.md) | Multi-dimensional metering including energy and carbon | Proposed |
| [0010](0010-transactional-outbox-no-broker.md) | Transactional outbox instead of a message broker | Accepted |
| [0011](0011-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0012](0012-ml-detectors-as-local-sidecar.md) | ML detectors run as an optional local sidecar | Accepted |
| [0013](0013-trunk-based-development-and-release-please.md) | Trunk-based development with Conventional Commits and release-please | Accepted |

## Template

```markdown
# ADR-NNNN: Title

- Status: Proposed
- Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Alternatives considered
```

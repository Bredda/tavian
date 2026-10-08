# ADR-0011: Apache-2.0 licence

- Status: Accepted (2026-10-08)
- Date: 2026-10-08

## Context
The primary audience is regulated organizations whose legal and procurement teams often prohibit copyleft network licences such as AGPL. The secondary audience (small teams, homelabs) is indifferent. The project is open source and a personal project, with no commercial constraint today.

## Decision
License the code under **Apache-2.0**. Documentation under the same licence unless stated otherwise. Contributions are accepted under the same terms (DCO sign-off to be defined with the contribution process).

## Consequences
- Maximum adoption in the target segment; explicit patent grant.
- Nothing prevents a third party from offering a closed hosted service based on the code. Accepted trade-off.
- A later relicensing to a more restrictive licence would need contributor agreement; keeping the contributor base small early keeps that option open if the situation changes.

## Alternatives considered
- AGPL-3.0 — blocks closed SaaS forks but is a procurement obstacle for the target audience.
- BSL / Elastic License 2.0 — not open source; discourages contributors.

# ADR-0002: Generic OIDC for identity; Keycloak as reference

- Status: Proposed
- Date: 2026-10-08

## Context
Keycloak is a natural on-prem IdP, but organizations already run Entra ID, Okta, Authentik, Dex or others. Coupling to Keycloak-specific features would exclude them.

## Decision
Tavian depends only on **standard OIDC** (discovery, JWKS, standard claims, a configurable claim for groups/roles). Keycloak is the reference setup shipped in the compose file and documented first. API keys are supported as a second credential type for applications, issued and verified by Tavian itself.

## Consequences
- Works with any compliant IdP; claim mapping (groups → teams/roles) must be configurable.
- Tavian never stores user passwords.
- JWKS caching and max-staleness behavior must be explicit (see ARCHITECTURE.md failure modes).

## Alternatives considered
- Built-in user database — more attack surface, duplicates the IdP.
- Keycloak-specific integration — narrower adoption.

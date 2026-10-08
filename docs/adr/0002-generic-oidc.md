# ADR-0002: Generic OIDC for identity; Keycloak as reference

- Status: Accepted (2026-10-08), implemented in M1
- Date: 2026-10-08

## Context
Keycloak is a natural on-prem IdP, but organizations already run Entra ID, Okta, Authentik, Dex or others. Coupling to Keycloak-specific features would exclude them.

## Decision
Tavian depends only on **standard OIDC** (discovery, JWKS, standard claims, a configurable claim for groups/roles). Keycloak is the reference setup shipped in the compose file and documented first. API keys are supported as a second credential type for applications, issued and verified by Tavian itself.

## Consequences
- Works with any compliant IdP; claim mapping (groups → teams/roles) must be configurable.
- Tavian never stores user passwords.
- JWKS caching and max-staleness behavior must be explicit (see ARCHITECTURE.md failure modes).

## Implementation notes (M1)
- Tokens are verified locally (JWS signature, `iss`, required `aud`, `exp` with a small clock skew, `sub`) with an asymmetric-only algorithm allow-list. There is no introspection call and no revocation: a token is valid until it expires, so keep access-token lifetimes short at the IdP.
- Signing keys come from `jwks_uri` or discovery, always through the egress guard, so the IdP must be a declared endpoint with a destination class the profile allows. They are cached in memory and refreshed periodically; an unknown `kid` triggers one rate-limited re-fetch (rotation); while the IdP is unreachable cached keys are trusted up to `jwks_max_staleness`, then every token is refused (fail closed). Metric: `tavian_oidc_jwks_age_seconds`.
- A provider that is down at startup is not fatal: tokens are refused, API keys keep working, and the fetch is retried with backoff.
- Authorization is configured, not derived from the IdP: `mappings` turn group membership into a team and allowed models. A person in no mapped group is authenticated but can use no model. The first matching mapping (configuration order) names the team; allowed models of all matching mappings add up.
- Each mapping also grants a clearance (`max_classification`, default `internal`); a person gets the highest clearance of their groups, like their allowed models add up. It is carried on the identity and enforced by the content policy in M2.
- API keys and tokens coexist: `tav_`-prefixed credentials are API keys, anything else goes to OIDC. Usage events carry `auth_method` and `user_id` (the token's `sub`) instead of `key_id`.

## Alternatives considered
- Built-in user database — more attack surface, duplicates the IdP.
- Keycloak-specific integration — narrower adoption.

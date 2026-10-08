# ADR-0008: Gateway is the single egress point; deployment profiles

- Status: Accepted (2026-10-08), implemented in M1
- Date: 2026-10-08

## Context
The hard constraint is air-gapped operation, yet some users want approved external providers. The two must coexist without weakening the guarantee.

## Decision
- Only the gateway data plane may open outbound connections, through one **egress guard** that resolves destinations from validated Backend configuration.
- Three **deployment profiles** — `air-gapped`, `controlled-egress`, `open-egress` — gate which destination classes (`internal`, `approved-external`, `public-external`) may exist. The profile is checked at config load and at dial time.
- Supported: outbound HTTP proxy, custom CA bundle, DNS pinning, allow-listed hosts.
- No telemetry, update check or licence check, in any profile.
- Deployment manifests ship network policies so the property is enforced by the platform, not only by the application.

## Consequences
- Misconfiguration cannot silently introduce egress in `air-gapped`.
- A CI rule must ensure no other package dials out.
- OTel exporters and similar integrations must also use validated internal endpoints.

## Implementation notes (M1)
- The guard covers model backends, the identity provider (JWKS/discovery) and PostgreSQL. Backend and IdP endpoints come from the configuration snapshot; the database endpoints come from the connection URL and are pinned at startup, always as `internal` whatever the profile (unix sockets are refused). pgx is configured to hand the guard host names, not pre-resolved addresses, so allow-list matching and the internal-address check apply to every connection.
- The CI rule is a `forbidigo` lint rule: `net.Dial*`, `net.Dialer`, name lookups, `tls.Dial*`, `http.DefaultClient`/`Get`/`Post`…, and direct pgx connections are forbidden outside `internal/egress` (and `internal/store`, which only connects with the guard's dialer).
- Not implemented yet: outbound HTTP proxy, custom CA bundle, DNS pinning, and the reference network policies.

## Alternatives considered
- Trust operators to firewall — insufficient as the only line of defence.
- Per-request egress decisions in policy only — policy errors would be the sole barrier.

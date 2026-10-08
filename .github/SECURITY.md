# Security policy

Tavian is a security-sensitive component: it sits between applications and LLMs and sees prompt content. We take vulnerability reports seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability reporting:
*Security tab → Report a vulnerability* on this repository.

Include what you found, how to reproduce it, the affected version or commit, and the impact you foresee. We aim to acknowledge reports within a few days and to agree on a disclosure timeline with you.

## Scope

In scope: the gateway (authentication, authorization, policy and quota enforcement, content inspection, egress control, audit integrity), its default configuration and the deployment manifests we ship.

Of particular interest: any way to make the gateway open a connection to a destination that is not a configured backend, bypass an authorization or policy decision, leak request content into logs or metrics, or tamper with audit records undetected.

## Supported versions

The project is pre-1.0. Security fixes are made on `main` and released as soon as possible; only the latest release is supported.

## Known limits

Content inspection is best-effort by design; see [docs/SECURITY.md](../docs/SECURITY.md#limits-and-residual-risk) for what is and is not guaranteed.

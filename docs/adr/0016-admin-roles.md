# ADR-0016: Roles of the administration API

- Status: Accepted (2026-10-10)
- Date: 2026-10-10

## Context
The first administration API ([ADR-0003](0003-config-snapshots-and-plane-separation.md), `docs/ADMIN_API.md`) had one kind of token: whoever held one could do everything, including replacing the whole configuration. [SECURITY.md](../SECURITY.md) names the insider administrator who weakens a policy or alters evidence (T6) as a threat, and an auditor who must be able to look without being able to touch. The open question (#83) was how strict to be for the first version: simple roles, or two-person approval and external anchoring from the start.

## Decision
Every admin token has a **role**, required in the configuration (`admin.tokens[].role`), with no default so that forgetting it cannot grant the most:

- **auditor**: reads (who am I, the running configuration, the revisions and their differences, the history of changes) and changes nothing;
- **operator**: what an auditor may, and checks a configuration (`validate`) and makes the gateway read its configuration file again (`reload`), which is an operation on what the deployment put in place, not a change of it;
- **admin**: everything, including `apply` and `rollback`.

Who may do what is decided in one place: each route of the API is declared with the permission it needs (`read`, `operate`, `change`), roles hold permissions, and no route is served without a declaration. A test lists every route and every role, and a second one checks that the OpenAPI description names, for every operation, the lowest role that may call it.

A call the role does not allow is `403 forbidden`. When it was an attempt to change something, it is **recorded** (rejected, `forbidden`, with the role) in the same way as any other refused change, so that probing leaves a trace. A configuration must keep at least one token with the role admin, or nobody could change it any more; it is refused otherwise.

The two-person approval of guardrail changes ([#56](https://github.com/Bredda/tavian/issues/56)) and the anchoring of seals outside the database and in a KMS ([#57](https://github.com/Bredda/tavian/issues/57)) are **not** part of the first version: they are M4 work, which builds on these roles and on the record of every change that already goes into the audit chain.

## Consequences
- An auditor or a CI job can be given a token that can read and never change, and an operator one that can reload but not rewrite the configuration.
- Roles are only as strong as who may write the configuration file and the token list: an admin can give any token any role, and that is recorded in the chain like every other change. Separating that power is what two-person approval is for.
- Roles of OIDC identities for administrators (#127) will map groups to these same roles.
- Tokens cannot yet expire or be rotated without editing the configuration (#128).

## Alternatives considered
- **A default role** (admin, for compatibility) — the API has not been released, so there is nothing to stay compatible with, and a missing line silently granting everything is the wrong failure.
- **Per-endpoint grants** (a list of permissions per token) — more flexible, harder to reason about and to audit than three named roles; can be added later without breaking the roles.
- **Two-person approval from the start** — the right answer for guardrails, but it needs a pending state, notifications and a reviewer role: a design of its own (#56), not a reason to delay roles.

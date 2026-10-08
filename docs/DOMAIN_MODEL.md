# Domain model

_Status: draft v0.1_

## Overview

```
Organization (one per deployment, for now)
 ├── Team ◄──────────── membership ───────────► User (from IdP)
 │     └── Application ── ApiKey
 │
 ├── Model (alias exposed to clients) ──► RoutePlan ──► Backend (concrete deployment)
 │
 ├── ClassificationScheme (ordered labels)
 ├── Ruleset (detectors configuration)
 ├── Policy ◄── PolicyBinding ──► scope (org | team | application | user)
 ├── Quota   ──► scope + dimension + window
 │
 └── produces ──► DecisionRecord · UsageEvent · AuditRecord
```

## Entities

### Identity

| Entity | Description |
|---|---|
| **Organization** | Root scope. One per deployment initially; multi-tenancy is deliberately deferred ([OPEN_QUESTIONS](OPEN_QUESTIONS.md)). |
| **User** | A human principal, identified by the IdP (`sub`). Created just-in-time from OIDC claims; never has a password in Tavian. |
| **Team** | A group of users, mapped from IdP group claims and/or managed in Tavian. Unit of budget and policy. |
| **Application** | A non-human consumer (service). Belongs to a team. Declares a **maximum classification** it is trusted to handle. |
| **ApiKey** | Credential for an application (or user). Stored hashed, scoped, expirable, revocable, with a visible prefix for identification. |
| **IdentityContext** | Per-request, derived: user, groups, team, application, auth method. The input to every later decision. |
| **Role** | RBAC role (`admin`, `security-admin`, `auditor`, `team-admin`, `user`, …). Admin roles are separated: the person who edits policy is not the person who can alter audit. |

### Catalog

| Entity | Description |
|---|---|
| **Model** | The name clients use (`llama-70b`, `gpt-x`). Has a **type** (`chat`, `embedding`, `rerank`, …) and **capabilities** (tools, vision, json mode, context window). A Model is *what is requested*. |
| **Backend** | A concrete place that can serve a model: provider type, endpoint, credentials reference, **destination class**, **max classification** it may receive, region, price (versioned), energy profile, health, limits. A Backend is *where it runs*. |
| **RoutePlan** | The mapping Model → ordered/weighted set of Backends plus a strategy (priority, round-robin, least-latency, least-cost, region-affinity, failover). |
| **VirtualModel** *(later)* | A Model whose target is a **Pipeline** (pre-processing → raw Model(s) → post-processing) instead of a plain RoutePlan. By making `Model → target` polymorphic from the start, raw models, aliases, multi-provider routing and virtual models are the same concept. |

**Destination classes:** `internal` · `approved-external` · `public-external`. Each Backend belongs to exactly one.

### Security

| Entity | Description |
|---|---|
| **ClassificationScheme** | Ordered labels, default `public < internal < confidential < restricted`. Configurable. |
| **Ruleset** | Versioned set of detector configurations (PII patterns, secret patterns, custom dictionaries, ML models) and what finding types they emit. Shipped as signed offline bundles. |
| **Finding** | Output of a detector: type, subtype, confidence, location, severity. Does not retain the matched text by default. |
| **Policy** | Declarative rules: allowed models, destinations by classification, actions on findings, response inspection mode, audit settings. Versioned. See [POLICY.md](POLICY.md). |
| **PolicyBinding** | Attaches a Policy to a scope (org, team, application, user). |

### Resource control

| Entity | Description |
|---|---|
| **Quota** | scope + dimension (`rpm`, `tpm`, `tokens_per_day`, `budget_eur_month`, `concurrency`, `energy_wh_month`, …) + limit + window + mode (`hard`/`soft`). |
| **Price** | Versioned per Backend and token type, with effective dates. A usage event stores the price snapshot used. |
| **EnergyProfile** | Per Backend/Model estimate of energy per token and the method/confidence behind it. |
| **CarbonIntensity** | Grid intensity per site/region (gCO₂e/kWh), configurable and versioned. |

### Records (append-only)

| Entity | Description |
|---|---|
| **DecisionRecord** | For every request, including refused ones: identity, requested model, label, findings summary, rules matched, constraints, chosen backend, outcome, reason codes. |
| **UsageEvent** | Tokens (in/out/cached/reasoning), cost €, energy Wh, carbon gCO₂e, latency, status. Basis of quotas reports and chargeback. |
| **AuditRecord** | Tamper-evident envelope: decision + (optional, encrypted) content + hash-chain link. See [SECURITY.md](SECURITY.md#audit). |
| **ConfigRevision** | Immutable, numbered snapshot of the whole configuration. Every DecisionRecord references the revision it was evaluated under. |

## Key invariants

1. A request is evaluated under exactly one `ConfigRevision`, recorded in its DecisionRecord.
2. A Backend can only be selected if its destination class is allowed by the effective constraints **and** its max classification ≥ the request label.
3. Policies only narrow: a narrower scope can never grant what a wider scope denies.
4. Records are append-only; corrections are new records.
5. No entity stores a plaintext credential: API keys are hashed, provider credentials are references to a secret store.

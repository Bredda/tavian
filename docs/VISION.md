# Vision

_Status: draft v0.1_

## Problem

Organizations adopt LLMs faster than they can govern them. Teams call whatever API they can reach, with whatever key they obtained, sending whatever data they have at hand. Security and compliance teams cannot answer basic questions: *who sent what data to which model, was it allowed, and what did it cost?*

Self-hosting models solves part of the sovereignty problem, but without a control point in front of them it solves nothing about identity, data leakage, budgets or evidence. And a "sovereign" gateway that cannot look at prompt content is only half sovereign: it can say who called, but not what left the building.

## Positioning

> **The LLM gateway for organizations that must prove who sent which data to which model — without exposing anything to the Internet.**

Three properties set Tavian apart from a generic LLM proxy. Each is a design driver, not a feature to bolt on later.

1. **Air-gapped by construction.** No runtime dependency on any external service, no telemetry, no phone-home. The gateway is the *only* component allowed to egress, and only to providers an admin explicitly configured.
2. **Content-aware security.** The gateway inspects prompts and responses locally (PII, secrets, data classification, prompt injection signals) and makes routing and policy decisions based on the *data*, not just on the user.
3. **Evidence, not just logs.** Every decision is explainable (which rule, which finding) and recorded in a tamper-evident audit trail, alongside multi-dimensional cost: money, energy and carbon.

## Guiding principles

1. **Fail closed.** If the gateway cannot establish that a request is allowed, it is refused. Availability never silently overrides a security decision.
2. **Zero egress by default.** Outbound connections exist only for configured external backends, go through a single egress guard, and are impossible in the `air-gapped` profile.
3. **Content is toxic waste.** Prompts and responses are the most sensitive data the gateway touches. Collect the minimum, encrypt what is kept, expire it, and never put it in logs, traces or metrics labels.
4. **The hot path never waits on the database.** The data plane serves from an in-memory configuration snapshot.
5. **Policy is data.** Declarative, versioned, testable, simulatable before enforcement, explainable after.
6. **Boring operations.** One binary and PostgreSQL are enough to run it. Everything else (Redis, object storage, dashboards) is optional and added only when scale demands it.
7. **Open standards at every boundary.** OIDC, OpenAI-compatible API, OpenTelemetry, Prometheus. No proprietary lock-in for users.
8. **Honest about limits.** Content inspection is best-effort. We document what is *not* guaranteed ([SECURITY.md](SECURITY.md#limits-and-residual-risk)).

## Personas

| Persona | Needs | Primary surface |
|---|---|---|
| **Platform engineer** (primary operator) | Install in an air-gapped environment, upgrade safely, operate with standard tooling | Helm/compose, config, metrics, runbooks |
| **Security / compliance officer** | Define data-handling rules, prove they were enforced, investigate incidents | Policies, audit trail, findings |
| **Team lead / budget owner** | Know and cap what their team consumes (€, tokens, energy) | Quotas, usage reports |
| **Application developer** | Call models with a standard SDK and get clear errors | OpenAI-compatible API |
| **Auditor** (read-only) | Verify controls without being able to alter anything | Audit export, integrity verification |

**Primary target:** regulated organizations (finance, public sector, health, defense, critical infrastructure) running their own GPUs and unable to expose data to the Internet.
**Secondary target:** small teams and homelabs who want a single governed entry point for their local models. This is served by a short path to a first running instance (one binary + PostgreSQL, a compose file), *not* by compromising the security model.

## Non-goals

Tavian deliberately does **not**:

- serve or host models (use vLLM, llama.cpp, TGI, … behind it);
- manage prompts, prompt versions or evaluation of answer quality;
- be an agent framework or orchestration platform (virtual models are pipelines on a *single* request, not agent loops);
- be a general-purpose API gateway;
- provide a chat UI;
- do invoicing — it produces usage and chargeback data, nothing more;
- cache responses (semantic caches create cross-user data leakage risks; revisit only with a strong isolation story);
- inspect images, audio or files in the first versions (multimodal content is blocked or passed through by explicit policy — see [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md)).

## The demo that defines success

If this scenario works end to end, the core thesis is proven:

> The **finance** team calls the gateway with an internal app. A request contains an IBAN. The inspector flags it, the classification becomes `confidential`, policy restricts destinations to `internal`, and the request is routed to the on-prem vLLM — even though the client asked for a model that also exists on an external provider. An external-only model request from the same team is refused with an explainable reason. The team's quota is decremented. An auditor opens the audit trail, sees the decision with the matching rule and findings, the cost in €, Wh and gCO₂e, and verifies the chain has not been tampered with.

Every milestone in the [roadmap](ROADMAP.md) is measured against getting closer to this scenario.

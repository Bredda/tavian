GAIIA = enterprise-grade sovereign LLM gatewayp. Control, Monitor et secure acces to LLM inside your organization.

- Proxy OpenAI-compatible LLM requests
- Control usage with fine-grained quotas for users
- Monitor everything, keep full visibility over your AI usage
- Deploy anywhere, self-hosted, on-premise, fully under your control.

Core value is: Identity → Policy → Routing → Metering → Audit, with hte hard constraints of being fully on-prem / air-gapped.

## Data plane

```
request
   ↓
authentication
   ↓
authorization
   ↓
quota check
   ↓
policy
   ↓
routing
   ↓
provider
   ↓
response
   ↓
async usage event
```

PostgreSQL is source of truth, Redis quick dstributed state.

## Authentification

                    Keycloak
                       │
                     OIDC
                       │
                       ▼

Application ────► Gateway
│
│ JWT
▼
Identity Context

## Policy engine

```
User
  ↓
Team
  ↓
Application
  ↓
Model
  ↓
Policy
  ↓
Quota
  ↓
Provider

```

Examples:

```yaml
policy:
  team: research

  models:
    allowed:
      - mistral-large
      - llama-70b
      - claude-sonnet

  quotas:
    requests_per_minute: 100
    tokens_per_minute: 200000
    tokens_per_day: 5000000
    budget_monthly_eur: 500

  restrictions:
    pii: block
    external_provider: false
```

```yaml
policy:
  team: finance

  models:
  allowed:
    - internal/*
    - azure/openai/*

  deny:
    - anthropic/*
    - openai/public/*

  data_policy:
  confidential: internal_only
```

## Qotas

- Rate limit: 100 requests / minute
- Token rate limit: 200k input + output tokens / minute
- Budget: €500 / month
- Concurrency: max 10 concurrent requests

```
                 ┌──────────────┐
Request ────────►│ Quota Engine │
                 └──────┬───────┘
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
       RPM             TPM             Budget
        │               │                │
        └───────────────┼────────────────┘
                        ▼
                     ALLOW
```

## Open telemetry

Requests receives:

```
trace_id
request_id
user_id
team_id
model
provider
```

Then:

```
Gateway
   │
   ├── auth span
   ├── policy span
   ├── quota span
   ├── routing span
   └── provider span
          │
          └── LLM
```

## Routing is independent from proxy

```
Model
 ├── provider
 ├── endpoint
 ├── capabilities
 ├── context_window
 ├── input_price
 ├── output_price
 └── health
```

Then:

```
"gpt-x"
   │
   ├── Azure Paris
   ├── Azure Frankfurt
   └── OpenAI EU

"llama-70b"
   │
   ├── GPU cluster A
   └── GPU cluster B
```

With strategies:

```
round robin
least latency
least cost
priority
failover
region affinity
data classification
```

## Sovereign architecture, not marketing

Sovereign:

```
Internet
   X
   │
   ▼
Gateway ──► Internal LLMs
   │
   ├── Keycloak
   ├── PostgreSQL
   ├── Redis
   ├── MinIO
   └── Grafana
```

Soverign + approved models:

```
Gateway
   │
   ├── internal models
   │
   └── Azure OpenAI EU
```

Hybrid

```
Gateway
   │
   ├── internal
   ├── approved external
   └── public external
```

With policies:

```
classification: confidential
allowed_destinations:
  - internal
  - azure_eu
```

## Proxy is openai compatible first

```
POST /v1/chat/completions
POST /v1/responses
GET  /v1/models
POST /v1/embeddings
```

## Potential MVP architecture

```
                        ┌──────────────┐
                        │   Keycloak   │
                        └──────┬───────┘
                               │ OIDC
                               ▼
┌─────────────┐       ┌─────────────────────┐
│ AI clients  │──────►│    LLM Gateway      │
└─────────────┘       │                     │
                      │ Go                  │
                      │                     │
                      │ Auth                │
                      │ Policy              │
                      │ Quota               │
                      │ Router              │
                      │ Provider adapters   │
                      │ Metering            │
                      └───┬────────┬────────┘
                          │        │
                    ┌─────▼──┐  ┌─▼──────┐
                    │ Redis  │  │Postgres│
                    └────────┘  └────────┘
                          │
                          ▼
                     ┌─────────┐
                     │  NATS   │
                     └────┬────┘
                          │
               ┌──────────┼──────────┐
               ▼          ▼          ▼
           Analytics    Audit      Billing

                          │
                          ▼
                 ┌─────────────────┐
                 │ Provider layer  │
                 └────┬────┬───────┘
                      │    │
                    vLLM  Azure
```

```
             Admin UI
                │
                ▼
          Control Plane
                │
        ┌───────┼────────┐
        ▼       ▼        ▼
     Policies Models  Users/Teams
```

## Potential mvp roadmap

v0.1

```
OIDC
   ↓
OpenAI-compatible proxy
   ↓
1 provider
   ↓
Postgres
   ↓
Usage tracking
```

v0.2

```
+ multiple providers
+ model registry
+ API keys
+ teams
+ quotas
+ Redis
```

v0.3

```
+ RBAC
+ policy engine
+ audit
+ Grafana
+ OpenTelemetry
+ admin UI
```

v0.4

```
+ data classification
+ DLP
+ prompt policies
+ model allow/deny
+ secret management
```

v1.0

```
+ HA
+ Kubernetes
+ air-gapped installation
+ multi-cluster
+ disaster recovery
+ enterprise policy packs
```

Others ideas to integrate

- Environmental cost as first class citizen, same as meny costs
- Going beyond LLM with embeddings, rerankers, system one models,...
- Possibility to extend "raw" models to create virtual ones, using pre/postprocess pipelines, middlewares, etc.

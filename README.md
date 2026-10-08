# Tavian

**Sovereign LLM gateway.** Identity, content security, policy, quotas, metering and audit for LLM access inside organizations that cannot afford to lose control of their data.

> **Status: pre-alpha — design phase.** Nothing is implemented yet. The documents below are a first draft meant to be challenged.

## What it is

A single entry point between your applications and your LLMs (self-hosted or approved external), exposing an OpenAI-compatible API and enforcing, on every request:

```
Identity → Content inspection → Policy → Routing → Quota → Metering → Audit
```

with one hard constraint: **it must run fully on-prem and air-gapped.** The only outbound traffic ever allowed is from the gateway to explicitly configured, online LLM providers.

## Quick start (demo)

Requires Docker. This starts the gateway in front of a mock OpenAI-compatible backend that sits on a network with no route to the Internet:

```bash
make demo
curl -s localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI' \
  -H 'Content-Type: application/json' \
  -d '{"model":"demo-chat","messages":[{"role":"user","content":"Bonjour"}]}'
make demo-down
```

The key above is public and for the demo only (`tavian keygen` makes real ones). Metrics and health are on `localhost:9090`. An annotated configuration lives in [configs/tavian.example.yaml](configs/tavian.example.yaml).

## What works today (M1 skeleton)

API-key authentication with per-key model allow-lists · `POST /v1/chat/completions` (streaming included) and `GET /v1/models` · OpenAI-compatible backends (vLLM, …) · strict configuration compiled into an immutable snapshot, reloadable with `SIGHUP` · egress guard enforcing the deployment profile · usage events with token counts · health, readiness and Prometheus metrics. Content inspection, policy, quotas, PostgreSQL storage and OIDC are next; see the [roadmap](docs/ROADMAP.md).

## Development

`make test`, `make lint`, `make build`. Workflow, commit conventions and releases are described in [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

| Document | Purpose |
|---|---|
| [docs/VISION.md](docs/VISION.md) | Problem, positioning, principles, personas, non-goals |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, deployment profiles, request lifecycle, failure modes |
| [docs/DOMAIN_MODEL.md](docs/DOMAIN_MODEL.md) | Core entities and their relationships |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, content inspection, data classification, egress control, audit |
| [docs/POLICY.md](docs/POLICY.md) | Policy model, evaluation semantics, examples, lifecycle |
| [docs/QUOTAS_AND_METERING.md](docs/QUOTAS_AND_METERING.md) | Quotas (reserve/settle), multi-dimensional metering incl. energy and carbon |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Scenario-driven milestones |
| [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md) | Decisions still to make, research still to do |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, trunk-based workflow, commit conventions, releases |
| [docs/adr/](docs/adr/README.md) | Architecture Decision Records |
| [BASELINE.md](BASELINE.md) | Original raw idea notes (historical) |

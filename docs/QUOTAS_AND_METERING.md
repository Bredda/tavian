# Quotas and metering

_Status: draft v0.1_

## Dimensions

Metering records several dimensions **per request from day one**. Adding a dimension later means rewriting history; recording it early and showing it later is cheap.

| Dimension | Notes |
|---|---|
| Tokens | input, output, cached, reasoning — kept separate because prices differ |
| Requests | count, status class |
| Cost (€) | tokens × price **snapshot at request time** (prices change) |
| Energy (Wh) | estimate, with `method` and `confidence` attached |
| Carbon (gCO₂e) | energy × grid carbon intensity of the backend's site/region |
| Latency | time to first token, total |

### Energy and carbon

Environmental cost is a first-class citizen, on par with money:

- Each Backend has an **EnergyProfile**: Wh per input/output token (or per request for non-LLM models), with a `method` — `measured` (e.g. GPU power telemetry from a local cluster) · `benchmark` (published figures for that model class) · `estimated` (generic fallback) — and a confidence.
- Each site/region has a configurable **CarbonIntensity** (gCO₂e/kWh), versioned over time, entered by the operator (no external API call — air-gapped).
- Energy and carbon can be capped by quotas (`energy_wh_month`, `co2e_g_month`) and surfaced in the same reports as cost.
- Figures are **estimates** and always labelled as such. The goal is comparability and awareness, not accounting-grade reporting.

## Quotas

| Dimension | Window | Typical use |
|---|---|---|
| `rpm` | sliding 1 min | Abuse protection |
| `concurrency` | instantaneous | Protect backends / GPUs |
| `tpm` | sliding 1 min | Fairness across teams |
| `tokens_per_day` | calendar day | Daily envelope |
| `budget_eur` | calendar month | Cost control |
| `energy_wh` / `co2e_g` | calendar month | Environmental budget |

- **Scopes:** organization, team, application, user. Every applicable scope must pass.
- **Modes:** `hard` (refuse) · `soft` (allow, flag, alert at thresholds such as 80% / 100%).
- Refusals return HTTP 429 with a stable error `code`, the limiting dimension and scope (not other tenants' data), and `Retry-After` when meaningful.

## Reserve / settle

Token consumption is only known after the response. To enforce limits honestly:

```
admission (cheap)      rpm, concurrency                       ← before inspection
reserve (after route)  estimated tokens + estimated cost      ← before provider call
        estimate = input_tokens_est + min(max_tokens, configured_default_cap)
settle (after call)    actual usage replaces the reservation; difference refunded or charged
```

Rules:

- **Input token estimate** comes from a tokenizer matching the model family when available, otherwise a conservative character-based estimate. The estimate errs on the high side; settle corrects it.
- **Output cap**: if the client omits `max_tokens`, a configured default cap is used for the reservation (and may be enforced upstream).
- **Streaming:** usage is taken from the provider's final chunk when present; otherwise counted locally from relayed chunks. If the stream is cut, settle with what was observed.
- **Idempotency:** settle is keyed by `request_id` so retries and crashes cannot double-count.
- **Crash recovery:** stale reservations expire (TTL) and are reconciled from usage events.
- **Budget in €** uses the price of the *selected* backend, which is why the reservation happens after routing.

## State and scaling

| Deployment | Counter storage |
|---|---|
| Single instance | In process memory, periodically checkpointed to PostgreSQL |
| Multiple replicas | Shared counters in Redis (atomic scripts for reserve/settle), PostgreSQL remains the source of truth for aggregates |

If the counter store is unavailable: **fail closed** by default. An optional degraded mode applies conservative per-instance local limits ([ARCHITECTURE.md](ARCHITECTURE.md#failure-modes)).

Soft-limit accuracy across replicas is eventually consistent by design; hard budget limits use the shared store.

## Reporting

Usage events are aggregated asynchronously (outbox → workers) into rollups by time bucket × team × application × user × model × backend. Chargeback exports (CSV/JSON) are provided; invoicing is a non-goal.

Metrics exposed to Prometheus use bounded labels (team, model, backend, outcome); per-user detail stays in PostgreSQL, not in metric labels.

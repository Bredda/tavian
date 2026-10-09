# Quotas and metering

_Status: draft v0.1. Quotas on requests, concurrency and tokens are built (see [In main](#in-main)); money, energy and carbon quotas arrive with prices and energy profiles (M2 step 2.7)._

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
        estimate = input_tokens_est + (max_tokens, else configured_default_cap)
settle (after call)    actual usage replaces the reservation; difference refunded or charged
```

Rules:

- **Input token estimate** comes from a tokenizer matching the model family when available, otherwise a conservative character-based estimate. The estimate errs on the high side; settle corrects it.
- **Output cap**: if the client omits `max_tokens`, a configured default cap is used for the reservation. When it sets one, that is what is reserved.
- **Streaming:** usage is taken from the provider's final chunk when present; otherwise counted locally from relayed chunks. If the stream is cut, settle with what was observed.
- **Idempotency:** settle is keyed by `request_id` so retries and crashes cannot double-count.
- **Crash recovery:** stale reservations expire (TTL) and are reconciled from usage events.
- **Budget in €** uses the price of the *selected* backend, which is why the reservation happens after routing.

## In main

Quotas are set in policies, in `spec.quotas` ([POLICY.md](POLICY.md#quotas)); this page describes how they are counted.

- **Dimensions:** `rpm`, `concurrency`, `tpm` and `tokens_per_day`. `budget_eur` is refused at load until prices exist (2.7); so will `energy_wh` and `co2e_g` be.
- **Scopes:** organization, team, application (user scope is refused for now: it would make the number of counters depend on callers instead of the configuration). Every applicable quota must pass; the most restrictive wins.
- **Counters** are keyed by scope and dimension, not by policy: the tokens a team used today are one fact whichever policies limit them, and renaming a policy resets nothing. Two policies limiting the same scope and dimension count each request once. Counters are outside the configuration snapshot, so a `SIGHUP` changes the limits and keeps the counts.
- **Windows:** `rpm` and `tpm` slide over the last 60 seconds in one-second buckets (exact to the second); `tokens_per_day` is a calendar day in **UTC**, reset at 00:00 UTC. The window of a dimension is fixed; a policy that names another one is refused at load.
- **Where:** `rpm` and `concurrency` are taken right after authentication, before the body is read, so a refused request costs no inspection time; a request refused later still counts against `rpm`, but a request refused *by* a quota counts against nothing (a refusal does not extend its own penalty). `tpm` and `tokens_per_day` are reserved after routing, just before the backend is called. Checking and counting every applicable counter is one atomic step, all or nothing.
- **Estimate:** the request body in bytes divided by three (a token is rarely fewer bytes, even in Chinese; English runs at about four, so the estimate errs high), plus the answer: the request's `max_tokens`, or `quota.default_output_tokens` (default 1024). The reservation is what the request *may* use, so a client asking for a huge `max_tokens` can be refused by a small `tpm` although its answer would be short. A request that alone is larger than a limit is refused as `quota_exceeded` without `Retry-After`: waiting cannot help.
- **Settle:** the tokens the backend reports (input plus output, reasoning included in output) replace the reservation, even above it: tokens already produced are owed and the next requests are refused until the window clears. If the backend reports nothing, a failed call gives everything back and a successful one keeps its estimate. A reservation settles once; there is no TTL because the counters die with the process. `tavian_quota_estimate_ratio` (used / reserved) shows how good the estimate is.
- **Refusals:** HTTP 429 with `Retry-After` (seconds until it would fit; to midnight UTC for `tokens_per_day`). The code is `rate_limit_exceeded` for `rpm`, `tpm` and `concurrency` (SDKs retry it) and `quota_exceeded` for `tokens_per_day` and for a request that can never fit (SDKs do not). The message names the dimension and the kind of scope, never the usage of others.
- **Modes:** `hard` refuses. `soft` counts and reports (the `quota` section of the decision record, `tavian_quota_exceeded_total{effect="soft"}`) without refusing. A policy in `shadow` mode is the same for all of its quotas.
- **Audit:** the decision record has a `quota` section: `reserved_tokens`, and every limit the request went over (policy, dimension, scope kind, limit, used, requested, effect). Refusals are recorded at most once per second for each caller and limit, with the number of refusals the record stands for (`suppressed`): a client that ignores its 429s must not fill the audit trail and put the whole gateway in fail-closed ([ADR-0005](adr/0005-fail-closed.md)). A refusal that is not recorded gets no `decision_id` (and no `X-Tavian-Decision-Id`); `tavian_quota_exceeded_total` counts every one.
- **Limits of this version:** counters are in memory and start from zero when the process restarts (the day's token count is rehydrated from the usage rollups once those exist, M2 step 2.6b), and they are per instance (shared counters: M3).

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

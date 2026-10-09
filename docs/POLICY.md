# Policy

_Status: draft v0.1. The schema below is the target; the next section says what the gateway implements today._

## What is implemented

*In main after v0.1.0*, policies are YAML files in a directory (`policy.dir` in `tavian.yaml`, relative to that file, reloaded with `SIGHUP`), each holding one or more `Policy` documents. The configuration revision covers the policy files, and each revision is stored with them, so a decision record's `config_revision` resolves to the exact rules that decided it. Existing deployments need `tavian migrate` once (migration 0002 adds the policy files to the stored revisions).

The **built-in baseline** is itself a policy in this format (`internal/policy/baseline.yaml`): the default label `internal`, the `destinations` table, and the rules that give `secret.*` the label `restricted` and IBANs, payment cards and NIRs `confidential`. It always applies and is the floor: your policies are intersected with it and can only narrow.

| Field | Status |
|---|---|
| `apiVersion: tavian/v1alpha1`, `kind: Policy`, `metadata.name` | required; names are unique across all files; `baseline` is reserved |
| `spec.scope` | `organization: true`, or `team` and/or `application` (both must match). `user` is refused: it needs RBAC (M3) |
| `spec.models.allow` / `deny` | implemented: a request is refused unless the credentials grant the model **and** every applicable policy with an allow list matches it **and** no applicable policy denies it |
| `spec.destinations` | implemented: label -> destination classes; the allowed set is the intersection over the applicable policies. A class the baseline does not allow has no effect (`tavian validate` warns) |
| `spec.classification.default` | implemented: the highest default among applicable policies |
| `spec.classification.infer` | implemented: CEL rules over `finding.*`, `identity.*`, `request.*`; the label is the highest of the rules that match |
| `spec.inspection.request.on_finding` | implemented: rules `{id, when, action, reason?, classes?}` evaluated once per kind of finding, with `label` available (see below) |
| `spec.inspection.on_error` | `block` only (the default): a request that cannot be inspected is always refused |
| `metadata.mode` | `enforce` (default) or `shadow`: see below |
| `spec.inspection.response`, `spec.inspection.request.rulesets` | not yet: refused at load with a message (response: M4; detectors are configured under `inspection:` in `tavian.yaml`) |
| `spec.quotas` | implemented: `{dimension, limit, window?, mode?}` for `rpm`, `concurrency`, `tpm`, `tokens_per_day`, `budget_eur` (see [Quotas](#quotas)) |
| `spec.audit` | not yet: refused at load (audit settings: M2 step 2.6 and M4) |

### Quotas

```yaml
spec:
  scope: { team: finance }
  quotas:
    - { dimension: rpm, limit: 120 }                  # requests in the last minute
    - { dimension: concurrency, limit: 10 }           # requests being served
    - { dimension: tpm, limit: 200000, mode: soft }   # tokens in the last minute
    - { dimension: tokens_per_day, limit: 5000000 }   # tokens since 00:00 UTC
    - { dimension: budget_eur, limit: 500 }           # euros since the 1st of the month, UTC (needs prices)
```

The limit belongs to the scope of the policy: `scope: { team: finance }` with `rpm: 120` is 120 requests a minute for the whole team, shared by its keys and users. Every quota of every applicable policy must pass. `mode` is `hard` (default, refuses with 429) or `soft` (counts and reports, never refuses); a policy in `shadow` mode behaves like `soft` for all of its quotas. A dimension can appear once per policy, and its window is fixed (`window` is optional and refused if it differs). How they are counted, estimated and recorded: [QUOTAS_AND_METERING.md](QUOTAS_AND_METERING.md#in-main). `tavian policy test` does not exercise quotas: they depend on what was used before.

### Actions on findings

A rule in `spec.inspection.request.on_finding` fires when its `when` is true for a kind of finding in the request (`finding.*` describes that kind; `label` is the effective label of the request). Its `action` is one of the following. When several rules fire the most restrictive wins, in this order:

| Action | Effect |
|---|---|
| `block` | Refuse the request: 403 `blocked_by_policy`, recorded under the rule's `reason` (an UPPER_SNAKE code such as `SECRET_IN_PROMPT`; default `POLICY_BLOCKED`). The caller sees the reason code and a `decision_id`, never the value. A block is decided before the clearance check |
| `restrict_destinations` | Keep the request off every destination class except those in `classes` (default: `internal` only), on top of the table for its label. Several rules intersect. The label is unchanged |
| `redact` | Replace every finding of that kind by a typed placeholder (`[IBAN_1]`, `[EMAIL_2]`; the same value gets the same number) before the request leaves the gateway. The text sent is the *normalized* text, with the replacements |
| `flag` | Record the rule in the decision record, nothing else |
| `allow` | Explicitly do nothing for this kind (it still appears in the record) |

`redact` is a protection on top of the label, not a way around it: **the label is computed from the findings of the original request**, so a request with a redacted IBAN is still `confidential` and still goes only to internal backends. After redacting, the gateway inspects what it is about to send and **refuses the request (`redaction_failed`, 500) if any redacted value is still there**, which also catches a value that only became detectable once its neighbour was replaced. If the request has more findings than the engine keeps (1000), it cannot be sure to have replaced them all and is refused (`redaction_incomplete`, 400). The decision record counts the redactions per kind, never the values. Redaction applies to every string of the request, like inspection.

### Shadow mode

A policy with `metadata.mode: shadow` is **evaluated for every request it applies to and enforces nothing**. The decision in force is exactly what it would be without it; the decision record gets a `shadow` section that says what the shadow policies would have changed: a block (`would_refuse`, with the rule's reason), a model they would have denied, a different label (and whether the caller's clearance would have been exceeded), different destinations, redactions that would have been made. The metric `tavian_policy_shadow_total{change}` counts them (`model`, `block`, `label`, `destinations`, `redact`, `clearance`, `error`), so a dashboard can show how many requests a candidate policy would affect before anyone turns it on. A shadow policy that fails to evaluate is reported in `shadow.error` and never fails the request. Switch to enforcement by removing `mode: shadow` and reloading. The built-in baseline is always enforced.

### Testing policies

`tavian policy test -config tavian.yaml fixtures.yaml...` (files or directories) runs fixtures against the configuration and policies. A case says who sends what (`caller`, `request`, and `content` to inspect with the configured detectors, or `findings` stated directly) and what must come out (`expect`: `outcome`, `reason`, `label`, `destinations`, `backend`, `redact`, `flagged`, `rules`, `shadow`); only what is given is checked. The cases run through `internal/pipeline`, the code the gateway itself uses to authorize the model, apply the policies, check the clearance, route and assert the route, so a passing fixture is a statement about the gateway and not about a copy of it. The exit status is 1 when a case fails: run it in CI next to your policy files. Examples: [configs/policy-tests/](../configs/policy-tests/) (`make policy-test`).

Anything not implemented is **refused when the policy is loaded**, never ignored, because a policy that silently does less than it says is worse than none. `tavian validate -config tavian.yaml` loads and checks the policies and prints warnings.

CEL conditions are type-checked when the policy is loaded, limited in size and cost, and evaluated once on a sample input, so a misspelled field (`finding.subtyp`) is an error at load time rather than at the first request that has a finding. A condition that fails on a real request (a division by zero, say) **fails the request closed** (`POLICY_ERROR`), naming the rule in the logs. Examples: [configs/policies/](../configs/policies/).

## Goals

- Express "who may use which model, for which data, under which limits" declaratively.
- Be **safe by default** (default deny), **explainable** (every decision cites the rules that produced it), **testable** (fixtures, simulation) and **distributable offline** (signed bundles).
- Avoid inventing a programming language: YAML for structure, [CEL](https://cel.dev) for conditions ([ADR-0006](adr/0006-policy-yaml-with-cel.md)).

## Scopes and inheritance

```
Organization  →  Team  →  Application  →  User
   (widest)                              (narrowest)
```

- **Default deny**: no matching allow means refusal.
- **Narrowing only**: a narrower scope can *restrict* what a wider scope allows, never extend it. Effective allow-sets are the **intersection** across scopes; any `deny` anywhere wins.
- The organization scope holds **guardrails** (e.g. "confidential data never leaves `internal`") that no team policy can relax.
- **Quotas** at every applicable scope must all pass.

## Evaluation: two phases

| Phase | When | Question | Output |
|---|---|---|---|
| **A — constraints** | After inspection, before routing | Given identity, requested model, label, findings: what is permitted? | Allowed destination classes, required transforms, or a denial |
| **B — assertion** | After routing, before the call | Does the chosen backend satisfy the constraints? | Pass, or refuse (indicates a routing bug) |

Before phase A, **model authorization** looks only at the identity and the model, so a refused model costs no inspection time.

Phase B is defence in depth: routing already filters on constraints, and this check ensures a bug there cannot leak data. It recomputes the constraints from the policies and the decision (including `restrict_destinations`), not from what routing was given.

*In main after v0.1.0:* both phases run with a built-in default (the `destinations` table and the finding-to-label inference, see [SECURITY.md](SECURITY.md#data-classification)); the YAML + CEL engine will load the same shapes from policy files.

### Action precedence on findings

When several rules match, the most restrictive action wins:

```
block  >  restrict_destinations  >  redact  >  flag  >  allow
```

## Schema (illustrative)

```yaml
apiVersion: tavian/v1alpha1
kind: Policy
metadata:
  name: finance-default
  description: Finance team — confidential data stays internal
spec:
  scope:
    team: finance

  models:
    allow: ["llama-70b", "mistral-large", "embed-*"]
    deny:  ["*-preview"]

  # label -> destination classes that may receive data of that label
  destinations:
    public:       [internal, approved-external, public-external]
    internal:     [internal, approved-external]
    confidential: [internal]
    restricted:   [internal]

  classification:
    default: internal           # team default label
    infer:                      # finding -> minimum label
      - when: finding.type == "pii" && finding.subtype in ["iban", "nir"]
        label: confidential
      - when: finding.type == "secret"
        label: restricted

  inspection:
    request:
      rulesets: [pii-fr@1, secrets@1, finance-codenames@3]
      on_finding:
        - when: finding.type == "secret"
          action: block
          reason: SECRET_IN_PROMPT
        - when: finding.type == "pii" && label.atLeast("confidential")
          action: restrict_destinations   # already implied by `destinations`, kept explicit
        - when: finding.subtype == "email"
          action: redact
    response:
      mode: observe               # off | observe | enforce
    on_error: block               # detector failure => block (default)

  quotas:
    - { dimension: rpm,              limit: 100,     window: 1m }
    - { dimension: tpm,              limit: 200000,  window: 1m }
    - { dimension: tokens_per_day,   limit: 5000000, window: 1d }
    - { dimension: budget_eur,       limit: 500,     window: month }
    - { dimension: concurrency,      limit: 10 }

  audit:
    content: hash                 # none | hash | redacted | full
    retention: 365d
```

An organization guardrail, for comparison:

```yaml
apiVersion: tavian/v1alpha1
kind: Policy
metadata:
  name: org-guardrails
spec:
  scope: { organization: true }
  destinations:
    confidential: [internal]
    restricted:   [internal]
  inspection:
    on_error: block
  audit:
    content: hash
```

Because scopes only narrow, the effective `destinations.confidential` for finance is `internal` even if a team policy tried to add `approved-external`.

## Condition language (CEL)

Available variables in `when:`:

| Variable | Content |
|---|---|
| `identity.*` | `user`, `groups`, `team`, `application`, `roles`, `auth_method` |
| `request.*` | `model`, `type`, `stream`, `max_tokens`, `has_tools`, `has_multimodal` |
| `finding.*` | `type`, `subtype`, `severity`, `confidence`, `count` (evaluated once per kind of finding: `confidence` and `severity` are the highest seen, `count` how many) |
| `label` | The effective classification label, with `label.atLeast("confidential")` for ordered comparison (CEL compares strings alphabetically). Available in `on_finding` rules; not in `infer` rules, which compute it |
| `route.*` | `backend`, `destination_class`, `region` (phase B only) |
| `time.*` | Time of day / weekday, for time-bound rules |

CEL is non-Turing-complete, side-effect free and bounded in cost, which makes policies safe to evaluate on the hot path and safe to accept from policy authors.

## Lifecycle

1. **Author** in YAML (Git is the recommended source of truth), or via the admin API.
2. **Validate**: schema, CEL type-check, referential integrity (models, rulesets), conflict and unreachable-rule linting.
3. **Test**: `tavian policy test` runs fixtures (`request + identity → expected decision`) in CI (implemented).
4. **Simulate**: replay recorded decision inputs (metadata, never content unless stored) against a candidate policy and diff the outcomes.
5. **Shadow**: deploy in `shadow` mode — evaluate and record "would have blocked", enforce nothing (implemented).
6. **Enforce**: publish a new `ConfigRevision`; optional two-person approval for guardrail changes.
7. **Distribute offline**: policies and rulesets are packaged as **signed bundles** that can be carried into air-gapped sites and verified on load.
8. **Roll back**: revisions are immutable; rollback = re-publish a previous revision.

## Explainability

Every `DecisionRecord` stores: config revision, rules evaluated and matched (by id), the label and its sources (declared / default / inferred), findings summary, constraints produced, chosen backend and why alternatives were excluded. A refused request returns a stable error `code` and a `decision_id`; the caller sees *that* and *which class of reason*, never the sensitive value that triggered it. Security and audit roles can see the full reasoning.

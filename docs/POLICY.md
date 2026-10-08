# Policy

_Status: draft v0.1 — the schema below is illustrative, not final._

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

Phase B is defence in depth: routing already filters on constraints, and this check ensures a bug there cannot leak data.

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
        - when: finding.type == "pii" && label >= "confidential"
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
| `finding.*` | `type`, `subtype`, `severity`, `confidence` (evaluated per finding) |
| `label` | The effective classification label (ordered comparison supported) |
| `route.*` | `backend`, `destination_class`, `region` (phase B only) |
| `time.*` | Time of day / weekday, for time-bound rules |

CEL is non-Turing-complete, side-effect free and bounded in cost, which makes policies safe to evaluate on the hot path and safe to accept from policy authors.

## Lifecycle

1. **Author** in YAML (Git is the recommended source of truth), or via the admin API.
2. **Validate**: schema, CEL type-check, referential integrity (models, rulesets), conflict and unreachable-rule linting.
3. **Test**: `tavian policy test` runs fixtures (`request + identity → expected decision`) in CI.
4. **Simulate**: replay recorded decision inputs (metadata, never content unless stored) against a candidate policy and diff the outcomes.
5. **Shadow**: deploy in `shadow` mode — evaluate and record "would have blocked", enforce nothing.
6. **Enforce**: publish a new `ConfigRevision`; optional two-person approval for guardrail changes.
7. **Distribute offline**: policies and rulesets are packaged as **signed bundles** that can be carried into air-gapped sites and verified on load.
8. **Roll back**: revisions are immutable; rollback = re-publish a previous revision.

## Explainability

Every `DecisionRecord` stores: config revision, rules evaluated and matched (by id), the label and its sources (declared / default / inferred), findings summary, constraints produced, chosen backend and why alternatives were excluded. A refused request returns a stable error `code` and a `decision_id`; the caller sees *that* and *which class of reason*, never the sensitive value that triggered it. Security and audit roles can see the full reasoning.

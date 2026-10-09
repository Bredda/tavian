# Open questions and decisions

_Status: living document._

**Open questions are `decision` issues on GitHub** ([open](https://github.com/Bredda/tavian/issues?q=is%3Aissue+label%3Adecision+is%3Aopen), [settled](https://github.com/Bredda/tavian/issues?q=is%3Aissue+label%3Adecision+is%3Aclosed)). Discuss and decide there; when one is settled, write the outcome down as an [ADR](adr/README.md) and close the issue with a link to it. This page keeps the answers that were already given before the move, for reference.

## Settled

- **Licence.** Apache-2.0 ([ADR-0011](adr/0011-apache-2-licence.md)), resolved 2026-10-08.
- **Small-deployment path.** PostgreSQL only, no SQLite mode; compensate with an excellent compose quick start ([ADR-0001](adr/0001-single-binary-postgres-baseline.md)), resolved 2026-10-08.
- **ML detectors runtime.** A local sidecar, optional, over a local socket ([ADR-0012](adr/0012-ml-detectors-as-local-sidecar.md)), resolved 2026-10-08. The detector interface is serializable for that reason.
- **Carbon accounting scope.** Operational electricity only, with the intensity entered by the operator per region and said so in the docs ([QUOTAS_AND_METERING.md](QUOTAS_AND_METERING.md#cost-energy-and-carbon-in-main)), 2026-10.

## Provisional answers (the open issue says what is still undecided)

- **Multimodal and files.** Requests with non-text content parts are refused (`multimodal_not_inspectable`), with no setting to relax it. An explicit `pass_through` is a decision issue.
- **Quota counters.** In memory, per instance; the day's tokens and the month's spending are rebuilt from the hourly usage sums at startup and reload; days and months are UTC.
- **Energy data.** The operator enters Wh per thousand tokens with a declared method and confidence; Tavian ships no default figures and claims no source.

## Not tracked here

The checks on the project name and trademark and the competitive analysis are kept outside the public repository.

## Regulatory context to review (not legal advice)

GDPR (data minimization, erasure, DPIA), EU AI Act (logging and transparency duties by risk class), NIS2, and French/EU qualification schemes for sovereign cloud (e.g. SecNumCloud). The goal is to make sure the audit and data-handling design can *support* these obligations, not to claim compliance. Tracked as a decision issue for v1.0.

# ADR-0014: Developer Certificate of Origin for contributions

- Status: Accepted (2026-10-09)
- Date: 2026-10-09

## Context
[ADR-0011](0011-apache-2-licence.md) licenses the code under Apache-2.0 and says that contributions come in under the same terms, with the sign-off "to be defined with the contribution process". The project has had a single author so far. Before external contributions are accepted we need to say what a contributor certifies, and how that is checked. Tavian is aimed at regulated organizations, whose legal teams look at the provenance of what they run.

## Decision
Contributions are accepted under the **Developer Certificate of Origin** (DCO 1.1, <https://developercertificate.org>). Every commit of a pull request carries a `Signed-off-by: Name <email>` line (`git commit -s`), and the email is that of the commit's author or committer.

- The check is `scripts/check-dco.sh`, run by the `dco` job of the CI on pull requests, and `dco` is a required check of `main`. It is our own script rather than a third-party GitHub App, to avoid an external dependency on the path to merge.
- Pull requests opened by Dependabot or release-please on a branch of this repository are exempt: those commits are made by tooling, not by someone certifying anything. The exemption is decided from the pull request's author and its head repository, which a fork cannot fake.
- The maintainer signs off like anyone else.
- No copyright assignment and no CLA: contributors keep their copyright.
- Security reports keep going through GitHub's private vulnerability reporting ([.github/SECURITY.md](../../.github/SECURITY.md)); that process does not change. Review rules do not change either: the maintainer merges, CI must be green, `main` is protected ([ADR-0013](0013-trunk-based-development-and-release-please.md)).

## Consequences
- A light barrier: one flag on `git commit`, no account to create, no document to sign.
- The sign-off is a certification by the contributor, not by us: the check verifies that it is there and matches the commit's identity, not that the statement is true.
- The sign-off lives in the pull request's commits. A squash merge may not repeat it in the final message; the pull request keeps the record.
- Relicensing to a more restrictive licence would need every contributor's agreement, since the DCO transfers no rights beyond the project's licence. This was already the position stated in ADR-0011; keeping the contributor base small early keeps the option open, and a CLA can replace the DCO later by a new ADR if the situation changes.
- Existing commits are not rewritten; the check only looks at the commits of each pull request.

## Alternatives considered
- **CLA** (for example with a CLA-assistant bot) — keeps relicensing simple but adds a legal document and an external service on the path to merge, and is an obstacle for the regulated organizations that would contribute fixes.
- **Nothing until the first external contribution** — contributions would then arrive without a stated basis, and the commits already merged would not set the habit.
- **A third-party DCO GitHub App** — less to maintain, but one more external service with access to the repository.

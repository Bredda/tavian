# ADR-0013: Trunk-based development with Conventional Commits and release-please

- Status: Accepted (2026-10-08)
- Date: 2026-10-08

## Context
We want a clean release process from the first commit: reproducible versions, an honest changelog, signed-off artifacts. Classic Gitflow (`develop`, `release/*`, `hotfix/*`) assumes scheduled releases and long-lived branches. release-please computes the next version from commit messages on a **single target branch** and maintains one release PR; the merge commits Gitflow produces on `develop`/`main` blur that computation. The project is small, mostly single-maintainer, and security fixes must ship quickly.

## Decision
- **Trunk-based:** `main` is always releasable; work happens on short-lived branches merged by pull request; unfinished work is hidden behind configuration, not long-lived branches.
- **Squash merge only**, linear history. The **PR title is the commit message** and must be a Conventional Commit; CI enforces it.
- **release-please** (manifest mode, `release-type: go`) maintains a release PR on `main`. Merging it creates the `vX.Y.Z` tag and GitHub release; CI then attaches binaries + checksums and publishes the container image to GHCR.
- Pre-1.0: `feat` → minor, `fix` → patch, breaking (`!`) → minor (`bump-minor-pre-major`). `1.0.0` is a deliberate decision.
- Maintenance branches `release/x.y` exist only when an older line needs a security backport.
- GitHub Actions are pinned by commit SHA (updated by Dependabot); workflows run with read-only tokens, jobs elevate individually.

## Consequences
- Simple mental model, fast hotfixes, accurate changelog; no `develop` to keep in sync.
- Discipline on PR titles is mandatory (hence the CI check).
- release-please PRs need a PAT/GitHub App token (`RELEASE_PLEASE_TOKEN`) for CI to run on them; documented in CONTRIBUTING.md.
- Supporting several release lines later needs per-branch release-please config.
- Artifact signing (cosign), SBOM and provenance attestations are not included yet; tracked in [#68](https://github.com/Bredda/tavian/issues/68) and [#91](https://github.com/Bredda/tavian/issues/91).

## Alternatives considered
- Gitflow with release-please — works poorly, see Context.
- Classic Gitflow with manual versioning — more ceremony and error-prone for a small team.
- GoReleaser for artifacts — good option, deferred to keep the initial pipeline small and auditable.

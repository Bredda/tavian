# Contributing

Tavian is pre-alpha and the design is still moving; read [docs/VISION.md](docs/VISION.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first, and open an issue before starting anything large.

## Development setup

Requirements: Go (see `go.mod`), Docker (for the demo stack), `golangci-lint` v2.

```bash
make test        # unit tests with the race detector
make lint        # golangci-lint
make build       # binaries in ./bin
make demo        # gateway + mock backend on localhost:8080, see README
```

No Go toolchain? The CI uses the same commands; locally you can run them through the `golang` Docker image.

## Workflow: trunk-based

`main` is always releasable. There is no `develop` branch.

1. Branch from `main` with a short-lived branch named `<type>/<short-description>` (`feat/oidc-auth`, `fix/stream-usage`). Keep it to a few days at most; split large work into independently mergeable steps and hide unfinished behaviour behind configuration rather than a long-lived branch.
2. Open a pull request. **The PR title is the commit message** (we squash-merge) and must follow [Conventional Commits](https://www.conventionalcommits.org): `type(scope): subject`. CI checks it.
3. CI must be green (`pr-title`, `lint`, `test`, `build`, `docker`, `workflows`). Squash-merge; the branch is deleted.

Commit types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`. Scope is optional, typically a package (`auth`, `config`, `egress`, `server`, `provider`, `policy`, …). The subject is lowercase, imperative, no trailing period. Mark breaking changes with `!` (`feat(config)!: rename listen.data`) and explain them in the PR description.

### Releases (release-please)

Versions and changelog are generated, never edited by hand.

- On every merge to `main`, release-please updates a single open PR titled `chore: release x.y.z` with the version bump and `CHANGELOG.md` entries computed from the squash commits.
- **Merging that PR is how a release is made**: it creates the tag `vX.Y.Z` and the GitHub release, then CI attaches binaries with checksums and publishes the container image to GHCR.
- While the project is `0.x`: `feat` bumps the minor version, `fix` the patch, and a breaking change (`!`) also bumps the minor. `1.0.0` is cut deliberately (`release-as`) when the API and configuration are declared stable.
- `refactor`, `test`, `build`, `ci` and `chore` are hidden from the release notes; `docs` and `perf` are listed. Only `feat`, `fix` and breaking changes are guaranteed to trigger a release.
- Hotfix = a normal `fix:` PR to `main` followed by merging the release PR. A `release/x.y` maintenance branch is created only if an older line must receive a security backport (cherry-pick through a PR).

### One-time repository setup (maintainers)

`scripts/setup-github-repo.sh OWNER/REPO` configures squash-only merges, branch protection on `main`, vulnerability alerts and private vulnerability reporting. It also explains the `RELEASE_PLEASE_TOKEN` secret that lets CI run on release PRs.

## Standards

- **Tests** with every change; `make test` must pass with `-race`.
- **Never log, trace or label metrics with request or response content**, API keys or backend credentials. Prompts are the most sensitive data this program touches.
- **Fail closed.** If a security decision cannot be made, refuse the request ([ADR-0005](docs/adr/0005-fail-closed.md)).
- **All outbound connections go through `internal/egress`** ([ADR-0008](docs/adr/0008-single-egress-point-and-deployment-profiles.md)). Do not use `http.DefaultClient` or dial directly in production code.
- **Significant decisions get an ADR** in `docs/adr/` (copy the template in its README). An accepted ADR is superseded by a new one, not rewritten.
- Dependencies are a liability here: prefer the standard library, and justify each new module in the PR.
- Keep documentation in sync with behaviour; `docs/` is the design source of truth.

## Reporting vulnerabilities

Do not open a public issue; see [.github/SECURITY.md](.github/SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under Apache-2.0 ([ADR-0011](docs/adr/0011-apache-2-licence.md)). A DCO sign-off requirement may be added later.

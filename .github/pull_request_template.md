<!--
The PR title becomes the commit message on main (squash merge) and drives the
version and changelog. Format: type(scope): subject — e.g. "feat(auth): add OIDC bearer validation".
Mark breaking changes with "!" — e.g. "feat(config)!: rename listen.data".
-->

## What and why

Closes #

## How to verify

## Checklist

- [ ] Commits are signed off (`git commit -s`, see CONTRIBUTING.md)
- [ ] Tests added or updated; `make test` passes
- [ ] No request or response content (prompts, completions, keys) is logged, traced or used as a metric label
- [ ] Docs updated (and an ADR added if this changes a significant decision)
- [ ] Breaking change? Described above and marked with `!` in the title

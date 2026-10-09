#!/usr/bin/env bash
# Developer Certificate of Origin check (ADR-0014): every commit in BASE..HEAD
# must carry a `Signed-off-by: Name <email>` line (git commit -s) whose email
# is the one of its author or its committer. Merge commits are not checked.
#
#   scripts/check-dco.sh origin/main HEAD
#
# CI runs it on pull requests; see the dco job in .github/workflows/ci.yml for
# who is exempt (Dependabot and release-please, on branches of this repository).
set -euo pipefail

base="${1:?usage: scripts/check-dco.sh BASE HEAD}"
head="${2:?usage: scripts/check-dco.sh BASE HEAD}"

failures=0
checked=0
while read -r sha; do
  checked=$((checked + 1))
  author="$(git log -1 --format=%ae "$sha" | tr '[:upper:]' '[:lower:]')"
  committer="$(git log -1 --format=%ce "$sha" | tr '[:upper:]' '[:lower:]')"
  ok=0
  has=0
  while IFS= read -r value; do
    [[ -n "$value" ]] || continue
    has=1
    if [[ "$value" =~ ^[^\<\>]+\ \<([^\<\>@\ ]+@[^\<\>@\ ]+)\>$ ]]; then
      email="$(tr '[:upper:]' '[:lower:]' <<<"${BASH_REMATCH[1]}")"
      if [[ "$email" == "$author" || "$email" == "$committer" ]]; then ok=1; fi
    fi
  done < <(git log -1 --format='%(trailers:key=Signed-off-by,valueonly,separator=%x0a)' "$sha")
  if ((ok == 0)); then
    failures=$((failures + 1))
    if ((has == 0)); then
      echo "::error::$(git log -1 --format='%h %s' "$sha"): no Signed-off-by line"
    else
      echo "::error::$(git log -1 --format='%h %s' "$sha"): Signed-off-by does not match the author ($author) or the committer ($committer), or is malformed"
    fi
  fi
done < <(git rev-list --no-merges "$base..$head")

if ((failures > 0)); then
  cat >&2 <<'EOF'

Every commit needs a sign-off, which certifies that you may submit the work
under the project's licence (https://developercertificate.org). To fix:

  git rebase --signoff origin/main && git push --force-with-lease   # add it to your commits
  git commit -s ...                                                  # for the next ones

See CONTRIBUTING.md.
EOF
  exit 1
fi
echo "$checked commit(s) checked, all signed off"

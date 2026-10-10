#!/usr/bin/env bash
# Close the open sub-issues of the given main issues, once the pull request that
# delivers them is merged. GitHub closes the issues a pull request names with
# `Closes #n`, not their sub-issues: this does, and the Project's "Item closed"
# automation then moves them to Done (CONTRIBUTING.md, "How work is tracked").
#
#   scripts/close-sub-issues.sh [-n] PULL_REQUEST ISSUE...
#
# -n only says what would be closed. Sub-issues labelled `decision` are left
# alone: a decision closes with its ADR, not with the step that waited for it.
# Needs gh, authenticated with a token that can write issues.
set -euo pipefail

dry=0
if [[ "${1:-}" == "-n" ]]; then dry=1; shift; fi
pr="${1:?usage: scripts/close-sub-issues.sh [-n] PULL_REQUEST ISSUE...}"
shift
[[ $# -gt 0 ]] || { echo "no issue closed by pull request #$pr: nothing to do"; exit 0; }
repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
[[ "$pr" =~ ^[0-9]+$ ]] || { echo "pull request must be a number" >&2; exit 2; }

for parent in "$@"; do
  [[ "$parent" =~ ^[0-9]+$ ]] || { echo "issue must be a number: $parent" >&2; exit 2; }
  mapfile -t subs < <(gh api --paginate "repos/$repo/issues/$parent/sub_issues?per_page=100" \
    --jq '.[] | select(.state == "open") | [.number, ([.labels[].name] | index("decision") != null)] | @tsv')
  if ((${#subs[@]} == 0)); then
    echo "#$parent: no open sub-issue"
    continue
  fi
  for line in "${subs[@]}"; do
    IFS=$'\t' read -r n is_decision <<<"$line"
    if [[ "$is_decision" == "true" ]]; then
      echo "#$parent: #$n is a decision, left open (it closes with its ADR)"
      continue
    fi
    if ((dry)); then
      echo "#$parent: would close #$n"
      continue
    fi
    gh api -X PATCH "repos/$repo/issues/$n" -f state=closed -f state_reason=completed >/dev/null
    gh api -X POST "repos/$repo/issues/$n/comments" -f body="Closed with #$parent by #$pr." >/dev/null
    echo "#$parent: closed #$n"
  done
done

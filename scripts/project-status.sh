#!/usr/bin/env bash
# Set the Status of issues on the project board.
#
#   scripts/project-status.sh [-n] "In progress" 27 33     # when work starts
#   scripts/project-status.sh [-n] "In review" 27 33       # when the pull request opens
#
# Statuses are those of the board: Backlog, Ready, In progress, In review, Done.
# Done comes by itself: merging closes the issues, and the board's "Item
# closed" automation does the rest (CONTRIBUTING.md). -n only says what would
# change. Needs gh authenticated with the `project` scope; the board is
# PROJECT_OWNER / PROJECT_NUMBER (defaults: Bredda, 7).
set -euo pipefail

usage="usage: scripts/project-status.sh [-n] STATUS ISSUE..."
dry=0
if [[ "${1:-}" == "-n" ]]; then dry=1; shift; fi
status="${1:?$usage}"
shift
[[ $# -gt 0 ]] || { echo "$usage" >&2; exit 2; }
[[ "$status" =~ ^[A-Za-z][A-Za-z\ ]*$ ]] || { echo "not a status name: $status" >&2; exit 2; }
owner="${PROJECT_OWNER:-Bredda}"
number="${PROJECT_NUMBER:-7}"

project="$(gh project view "$number" --owner "$owner" --format json --jq .id)"
# shellcheck disable=SC2016 # $p is a GraphQL variable, not a shell one
status_field='query($p: ID!) { node(id: $p) { ... on ProjectV2 { field(name: "Status") { ... on ProjectV2SingleSelectField { id options { id name } } } } } }'
field_id="$(gh api graphql -f query="$status_field" -f p="$project" --jq .data.node.field.id)"
option_id="$(gh api graphql -f query="$status_field" -f p="$project" \
  --jq ".data.node.field.options[] | select(.name == \"$status\") | .id")"
[[ -n "$option_id" ]] || { echo "the board has no status called \"$status\"" >&2; exit 1; }

for n in "$@"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "issue must be a number: $n" >&2; exit 2; }
  item="$(gh project item-list "$number" --owner "$owner" --limit 1000 --format json \
    --jq ".items[] | select(.content.number == $n) | .id" | head -n 1)"
  if [[ -z "$item" ]]; then
    echo "#$n: not on the board" >&2
    continue
  fi
  if ((dry)); then
    echo "#$n: would be set to \"$status\""
    continue
  fi
  gh project item-edit --project-id "$project" --id "$item" --field-id "$field_id" --single-select-option-id "$option_id" >/dev/null
  echo "#$n: $status"
done

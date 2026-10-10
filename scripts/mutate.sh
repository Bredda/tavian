#!/usr/bin/env bash
# Mutation check of one package: apply each mutant of its manifest, run the
# package's tests, and report whether they noticed. A mutant that survives is a
# behaviour no test pins down.
#
#   scripts/mutate.sh ./internal/cost       # or: make mutate PKG=./internal/cost
#   MUTATE_TIMEOUT=300 scripts/mutate.sh ./internal/quota
#
# The manifest is scripts/mutants/<package path with / as _>.txt (internal_cost.txt).
# One mutant per line, three TAB-separated fields; '#' starts a comment:
#
#   file<TAB>old<TAB>new
#
# `file` is relative to the repository root. `old` must occur exactly once in it
# (a fragment that does not carry the indentation); `new` replaces it. Write
# mutants that still compile and change behaviour: flip a comparison, drop a
# bound, swap a constant. A mutant that does not apply or does not compile is
# reported as INVALID (the manifest is stale) and counts as a failure, like a
# survivor.
#
# Rules: the files named in the manifest must be committed and unmodified, the
# tests must pass before any mutation, and nothing else may touch the working
# tree while this runs. Each file is restored from git after every mutant, also
# on Ctrl-C. Tests that need PostgreSQL read TAVIAN_TEST_DATABASE_URL from the
# environment, as usual.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

pkg="${1:-}"
[[ -n "$pkg" ]] || { echo "usage: scripts/mutate.sh ./internal/<package>" >&2; exit 2; }
dir="${pkg#./}"
dir="${dir%/}"
manifest="scripts/mutants/${dir//\//_}.txt"
[[ -f "$manifest" ]] || { echo "no manifest: $manifest" >&2; exit 2; }
timeout_s="${MUTATE_TIMEOUT:-120}"

mapfile -t mutants < <(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$manifest")
((${#mutants[@]} > 0)) || { echo "$manifest has no mutants" >&2; exit 2; }

declare -A seen=()
for line in "${mutants[@]}"; do
  IFS=$'\t' read -r file _ _ <<<"$line"
  seen[$file]=1
done
for file in "${!seen[@]}"; do
  [[ -f "$file" ]] || { echo "$manifest: $file does not exist" >&2; exit 2; }
  git ls-files --error-unmatch -- "$file" >/dev/null 2>&1 || { echo "$file is not tracked by git" >&2; exit 2; }
  git diff --quiet HEAD -- "$file" || { echo "$file has uncommitted changes: commit them first" >&2; exit 2; }
done

restore() {
  local f
  for f in "${!seen[@]}"; do git checkout -q HEAD -- "$f"; done
}
trap restore EXIT
trap 'exit 130' INT TERM

runtests() { timeout "$((timeout_s + 30))" go test -count=1 -timeout "${timeout_s}s" "$pkg" 2>&1; }

echo "baseline: go test $pkg"
if ! runtests >/dev/null; then
  echo "the tests fail before any mutation; fix them first" >&2
  exit 2
fi

killed=0 survived=0 invalid=0 n=0
for line in "${mutants[@]}"; do
  n=$((n + 1))
  IFS=$'\t' read -r file old new <<<"$line"
  if [[ -z "$file" || -z "$old" ]]; then
    echo "  INVALID   #$n: malformed line (need file<TAB>old<TAB>new)"
    invalid=$((invalid + 1))
    continue
  fi
  # exactly one occurrence, replaced literally (no regular expression)
  if ! OLD="$old" NEW="$new" perl -0777 -i -pe '
        $o = $ENV{OLD};
        $c = () = /\Q$o\E/g;
        if ($c == 1) { s/\Q$o\E/$ENV{NEW}/ } else { $bad = 1 }
        END { $? = 3 if $bad }' "$file"; then
    echo "  INVALID   #$n: '$old' does not occur exactly once in $file"
    invalid=$((invalid + 1))
    restore
    continue
  fi
  out="$(runtests)" && status=0 || status=$?
  restore
  if ((status == 0)); then
    echo "  SURVIVED  #$n: $file: '$old' -> '$new'"
    survived=$((survived + 1))
  elif grep -q -e '\[build failed\]' -e '\[setup failed\]' <<<"$out"; then
    echo "  INVALID   #$n: does not compile: $file: '$old' -> '$new'"
    invalid=$((invalid + 1))
  else
    echo "  killed    #$n: $file: '$old' -> '$new'"
    killed=$((killed + 1))
  fi
done

echo "$pkg: $killed killed, $survived survived, $invalid invalid (of $n)"
((survived == 0 && invalid == 0))

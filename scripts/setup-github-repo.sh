#!/usr/bin/env bash
# One-time GitHub repository setup for trunk-based development with release-please.
#
#   scripts/setup-github-repo.sh OWNER/REPO
#
# Run it once the repository exists and the first commit has been pushed to
# `main` (branch protection needs the branch to exist). Requires an
# authenticated `gh` with admin rights on the repository. Re-running it is safe.
set -euo pipefail

repo="${1:?usage: $0 OWNER/REPO}"

echo ">> merge policy: squash only, PR title becomes the commit message"
gh api -X PATCH "repos/${repo}" \
  -F allow_squash_merge=true \
  -F allow_merge_commit=false \
  -F allow_rebase_merge=false \
  -F delete_branch_on_merge=true \
  -F allow_auto_merge=true \
  -f squash_merge_commit_title=PR_TITLE \
  -f squash_merge_commit_message=BLANK >/dev/null

echo ">> Actions: read-only token by default; allow release-please to open PRs"
gh api -X PUT "repos/${repo}/actions/permissions/workflow" \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=true >/dev/null

echo ">> branch protection on main"
gh api -X PUT "repos/${repo}/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["pr-title", "lint", "test", "build", "docker", "workflows", "conformance", "demo", "dco"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

echo ">> security features"
gh api -X PUT "repos/${repo}/vulnerability-alerts" >/dev/null
gh api -X PUT "repos/${repo}/private-vulnerability-reporting" >/dev/null

echo ">> labels and milestones (see CONTRIBUTING.md, \"How work is tracked\")"
label() { gh label create "$1" --color "$2" --description "$3" -R "${repo}" --force >/dev/null; }
label epic 3E4B9E "A group of related issues"
label decision D4A017 "A question to settle (record the outcome in an ADR)"
label chore C5DEF5 "Maintenance, tooling, debt"
label area:api 0E8A16 "API surface and admin"
label area:audit 0E8A16 "Decision records, chain, seals, retention"
label area:inspection 0E8A16 "Content inspection and detectors"
label area:ops 0E8A16 "Operations, deployment, observability"
label area:policy 0E8A16 "Policy engine"
label area:quota 0E8A16 "Quotas, metering, cost"
label area:routing 0E8A16 "Models, backends, routing"
label area:security 0E8A16 "Security hardening"
label area:ui 0E8A16 "Admin UI"
existing="$(gh api "repos/${repo}/milestones?state=all&per_page=100" -q '.[].title')"
milestone() { grep -qxF "$1" <<<"${existing}" || gh api "repos/${repo}/milestones" -f title="$1" -f description="$2" >/dev/null; }
milestone "M3 — Operability" "Run it in production: admin API, registry with health and failover, embeddings, observability, multi-replica, chargeback export, TLS. See docs/ROADMAP.md."
milestone "M4 — Security depth" "Response inspection, ML detectors, content audit with encryption, signed bundles, external anchoring, secret stores, /v1/messages."
milestone "M5 — Platform" "Admin UI, virtual models, non-LLM models, energy and carbon quotas."
milestone "v1.0 — Production grade" "HA and Kubernetes, air-gapped bundle, multi-site, policy packs, signed releases."
milestone "Later" "Not scheduled: decisions pending or waiting for demand."

cat <<'EOF'

Done. Remaining manual step: create a fine-grained personal access token
(or a GitHub App) with "Contents" and "Pull requests" read/write on this
repository and store it as the Actions secret RELEASE_PLEASE_TOKEN. Without
it, release-please PRs are opened with GITHUB_TOKEN and their CI checks never
start, which blocks merging them under branch protection.
EOF

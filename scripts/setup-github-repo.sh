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
    "contexts": ["pr-title", "lint", "test", "build", "docker", "workflows", "conformance"]
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

cat <<'EOF'

Done. Remaining manual step: create a fine-grained personal access token
(or a GitHub App) with "Contents" and "Pull requests" read/write on this
repository and store it as the Actions secret RELEASE_PLEASE_TOKEN. Without
it, release-please PRs are opened with GITHUB_TOKEN and their CI checks never
start, which blocks merging them under branch protection.
EOF

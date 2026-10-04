#!/usr/bin/env bash
# Publish dsh-proof to GitHub using YOUR OWN credentials.
#
# This script deliberately never accepts, reads, or embeds a token. It relies
# on whatever authentication you have already configured for git/gh on this
# machine (SSH key, `gh auth login`, or a credential helper).
#
# Usage:
#   ./scripts/publish-github.sh git@github.com:YOU/dsh-proof.git
#   ./scripts/publish-github.sh https://github.com/YOU/dsh-proof.git
#   ./scripts/publish-github.sh <remote-url> --set-origin   # also set origin
set -euo pipefail

REPO_URL="${1:-}"
if [[ -z "$REPO_URL" ]]; then
  echo "usage: $0 <git-remote-url> [--set-origin]" >&2
  echo "  e.g. $0 git@github.com:your-name/dsh-proof.git" >&2
  exit 2
fi
shift || true

cd "$(dirname "$0")/.."

# --- refuse to run with a token in the URL ---------------------------------
if [[ "$REPO_URL" == *"@"* && "$REPO_URL" != git@* && "$REPO_URL" != ssh://* ]]; then
  echo "refusing: the remote URL embeds credentials." >&2
  echo "use https://github.com/OWNER/REPO.git (your git credential helper supplies auth)" >&2
  echo "or     git@github.com:OWNER/REPO.git    (your SSH key supplies auth)" >&2
  exit 1
fi

# --- identity ---------------------------------------------------------------
if ! git config user.name >/dev/null 2>&1 || ! git config user.email >/dev/null 2>&1; then
  echo "git identity not set for this repository." >&2
  echo "run:" >&2
  echo "  git config user.name  'Your Name'" >&2
  echo "  git config user.email 'you@example.com'" >&2
  exit 1
fi

if git config user.name | grep -q 'YOUR_GITHUB_USERNAME'; then
  echo "refusing: git identity is still the placeholder." >&2
  echo "  git config user.name  'Your Name'" >&2
  echo "  git config user.email 'you@example.com'" >&2
  echo "  git commit --amend --reset-author --no-edit" >&2
  exit 1
fi

# --- final local verification ----------------------------------------------
echo "==> typecheck";  npm run typecheck
echo "==> test";       npm test
echo "==> build";      npm run build
echo "==> bundle";     npm run bundle:check

# --- push -------------------------------------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if git remote get-url origin >/dev/null 2>&1; then
  echo "==> origin already set: $(git remote get-url origin)"
  if [[ "${1:-}" == "--set-origin" ]]; then
    git remote set-url origin "$REPO_URL"
    echo "==> origin updated to $REPO_URL"
  fi
else
  git remote add origin "$REPO_URL"
  echo "==> origin set to $REPO_URL"
fi

echo "==> pushing $BRANCH"
if git ls-remote --exit-code origin "$BRANCH" >/dev/null 2>&1; then
  git push origin "$BRANCH"
else
  git push -u origin "$BRANCH"
fi

cat <<'EOF'

pushed.

Next (on github.com — repository page -> About -> Settings -> Topics):
  add the topic:  dsh-plugin
That is the official discoverability convention; the community awesome lists
index repositories carrying it.
EOF

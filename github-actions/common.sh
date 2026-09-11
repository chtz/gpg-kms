#!/usr/bin/env bash
# Shared helpers for github-actions/*.sh. Source this file; do not execute.
# Honors AWS_PROFILE the same way kmslambda/common.sh does. Does not print account IDs.

GHA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DIR="$GHA_DIR/.local"
REPO_ROOT="$(cd "$GHA_DIR/.." && pwd)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required but was not found on PATH." >&2
    exit 1
  fi
}

require_aws() {
  require_cmd aws
}

init_aws() {
  require_aws
  PROFILE="${AWS_PROFILE:-}"
  REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

  if [[ -z "$REGION" ]]; then
    if [[ -n "$PROFILE" ]]; then
      REGION="$(aws configure get region --profile "$PROFILE" || true)"
    else
      REGION="$(aws configure get region || true)"
    fi
  fi

  if [[ -z "$REGION" ]]; then
    echo "Could not determine AWS region. Set AWS_REGION or configure a region for AWS_PROFILE." >&2
    exit 1
  fi
}

aws_cli() {
  local -a extra=(--region "$REGION")
  if [[ -n "${PROFILE:-}" ]]; then
    extra+=(--profile "$PROFILE")
  fi
  aws "${extra[@]}" "$@"
}

require_account() {
  ACCOUNT_ID="$(aws_cli sts get-caller-identity --query Account --output text)"
  if [[ -z "$ACCOUNT_ID" || "$ACCOUNT_ID" == "None" ]]; then
    echo "Could not determine AWS account id. Check AWS_PROFILE and SSO login." >&2
    exit 1
  fi
}

resolve_github_repo() {
  if [[ -n "${GITHUB_REPO:-}" ]]; then
    return 0
  fi
  GITHUB_REPO="${GITHUB_REPOSITORY:-}"
  if [[ -z "$GITHUB_REPO" ]] && command -v gh >/dev/null 2>&1; then
    GITHUB_REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
  fi
  if [[ -z "$GITHUB_REPO" ]]; then
    local local_url
    local_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
    if [[ "$local_url" =~ github.com[:/](.+/[^/.]+)(\.git)?$ ]]; then
      GITHUB_REPO="${BASH_REMATCH[1]}"
    fi
  fi
  if [[ -z "$GITHUB_REPO" || "$GITHUB_REPO" != */* ]]; then
    echo "Could not determine GitHub OWNER/REPO. Pass --repo OWNER/REPO." >&2
    exit 1
  fi
}

# Owner/repo numeric IDs for GitHub's immutable OIDC `sub` (repos created after 15 Jul 2026).
# CloudTrail userIdentity.userName is the actual `sub` if AssumeRoleWithWebIdentity is denied.
resolve_github_ids() {
  GITHUB_OWNER="${GITHUB_OWNER:-${GITHUB_REPO%%/*}}"
  GITHUB_REPO_NAME="${GITHUB_REPO_NAME:-${GITHUB_REPO#*/}}"
  if [[ -n "${GITHUB_OWNER_ID:-}" && -n "${GITHUB_REPO_ID:-}" ]]; then
    return 0
  fi
  require_cmd gh
  local meta
  meta="$(gh api "repos/${GITHUB_REPO}" --jq '[.owner.login, (.owner.id|tostring), .name, (.id|tostring)] | @tsv')"
  IFS=$'\t' read -r GITHUB_OWNER GITHUB_OWNER_ID GITHUB_REPO_NAME GITHUB_REPO_ID <<<"$meta"
  if [[ -z "$GITHUB_OWNER" || -z "$GITHUB_OWNER_ID" || -z "$GITHUB_REPO_NAME" || -z "$GITHUB_REPO_ID" ]]; then
    echo "Could not read GitHub owner/repo IDs from gh api repos/${GITHUB_REPO}." >&2
    echo "Pass --owner-id and --repo-id." >&2
    exit 1
  fi
}

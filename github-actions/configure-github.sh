#!/usr/bin/env bash
# Create the GitHub Environment used by release-jar.yml and set its secret/vars.
# Does not print secret values. Does not call AWS if role.env (or AWS_ROLE_ARN) is already set.
# Usage: configure-github.sh [--repo OWNER/REPO] [--role-name NAME]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_NAME="release"
BRANCH="main"

usage() {
  echo "Usage: $0 [--repo OWNER/REPO] [--role-name NAME]" >&2
  echo "Env: GITHUB_REPOSITORY, AWS_ROLE_ARN, AWS_ROLE_NAME, AWS_REGION," >&2
  echo "     KMSPGP_LAMBDA_FUNCTION_NAME" >&2
  echo "Source kmslambda/config.sh and github-actions/.local/role.env first." >&2
  exit 1
}

GITHUB_REPO="${GITHUB_REPOSITORY:-}"
ROLE_ARN="${AWS_ROLE_ARN:-}"
ROLE_NAME="${AWS_ROLE_NAME:-gha-gpg-kms-release}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) [[ $# -ge 2 ]] || usage; GITHUB_REPO="$2"; shift 2 ;;
    --role-name) [[ $# -ge 2 ]] || usage; ROLE_NAME="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

require_cmd gh

if [[ -f "$LOCAL_DIR/role.env" ]]; then
  # shellcheck source=/dev/null
  source "$LOCAL_DIR/role.env"
  ROLE_ARN="${AWS_ROLE_ARN:-$ROLE_ARN}"
  ROLE_NAME="${AWS_ROLE_NAME:-$ROLE_NAME}"
fi

resolve_github_repo

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
FUNCTION="${KMSPGP_LAMBDA_FUNCTION_NAME:-}"

if [[ -z "$ROLE_ARN" ]]; then
  echo "AWS_ROLE_ARN is not set. Run setup-oidc-role.sh first and source github-actions/.local/role.env." >&2
  exit 1
fi
if [[ -z "$REGION" ]]; then
  echo "AWS_REGION is not set. Source kmslambda/config.sh." >&2
  exit 1
fi
if [[ -z "$FUNCTION" ]]; then
  echo "KMSPGP_LAMBDA_FUNCTION_NAME is not set. Source kmslambda/config.sh." >&2
  exit 1
fi

echo "Configuring GitHub Environment '$ENV_NAME' for $GITHUB_REPO" >&2
echo "  branch:   $BRANCH" >&2
echo "  role:     $ROLE_NAME" >&2
echo "  region:   $REGION" >&2
echo "  function: $FUNCTION" >&2
echo >&2

gh api --method PUT "repos/${GITHUB_REPO}/environments/${ENV_NAME}" \
  --input - >/dev/null <<EOF
{
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
EOF

existing_policy="$(gh api "repos/${GITHUB_REPO}/environments/${ENV_NAME}/deployment-branch-policies" \
  --jq ".branch_policies[] | select(.name==\"${BRANCH}\" and .type==\"branch\") | .id" 2>/dev/null || true)"
if [[ -z "$existing_policy" ]]; then
  gh api --method POST "repos/${GITHUB_REPO}/environments/${ENV_NAME}/deployment-branch-policies" \
    -f name="$BRANCH" -f type=branch >/dev/null
  echo "Restricted environment deployments to branch '$BRANCH'." >&2
else
  echo "Environment already restricted to branch '$BRANCH'." >&2
fi

gh secret set AWS_ROLE_ARN --repo "$GITHUB_REPO" --env "$ENV_NAME" --body "$ROLE_ARN"
echo "Set environment secret AWS_ROLE_ARN." >&2

gh variable set AWS_REGION --repo "$GITHUB_REPO" --env "$ENV_NAME" --body "$REGION"
echo "Set environment variable AWS_REGION." >&2
gh variable set KMSPGP_LAMBDA_FUNCTION_NAME --repo "$GITHUB_REPO" --env "$ENV_NAME" --body "$FUNCTION"
echo "Set environment variable KMSPGP_LAMBDA_FUNCTION_NAME." >&2
if gh variable delete KMSPGP_LAMBDA_API_BASE_URL --repo "$GITHUB_REPO" --env "$ENV_NAME" >/dev/null 2>&1; then
  echo "Removed leftover environment variable KMSPGP_LAMBDA_API_BASE_URL." >&2
fi

echo >&2
echo "GitHub Environment '$ENV_NAME' is ready. Trigger .github/workflows/release-jar.yml on $BRANCH." >&2

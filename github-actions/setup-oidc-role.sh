#!/usr/bin/env bash
# Create or update the GitHub Actions OIDC IAM role for kmslambda signing.
# Filled policy documents stay in .local/ (gitignored). Sourceable exports on stdout.
# Honors AWS_PROFILE. Usage: setup-oidc-role.sh [--repo OWNER/REPO] [--role-name NAME] [--function LAMBDA]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

TRUST_TEMPLATE="$SCRIPT_DIR/trust-policy.json"
PERMS_TEMPLATE="$SCRIPT_DIR/permissions-policy.json"
GITHUB_OIDC_URL="https://token.actions.githubusercontent.com"
GITHUB_OIDC_HOST="token.actions.githubusercontent.com"
# GitHub-documented thumbprints; AWS no longer validates them for this issuer.
GITHUB_OIDC_THUMBPRINTS=("6938fd4d98bab03faadb97b34396831e3780aea1" "1c58a3a8518e8759bf075b76b750d4f2df264fcd")
INLINE_POLICY_NAME="invoke-kmslambda"

usage() {
  echo "Usage: $0 [--repo OWNER/REPO] [--role-name NAME] [--function LAMBDA] [--owner-id ID] [--repo-id ID]" >&2
  echo "Env: AWS_PROFILE, AWS_REGION, GITHUB_REPOSITORY, AWS_ROLE_NAME, KMSPGP_LAMBDA_FUNCTION_NAME" >&2
  echo "Default role name: gha-gpg-kms-release" >&2
  echo "Source kmslambda/config.sh so KMSPGP_LAMBDA_FUNCTION_NAME is set." >&2
  echo "Owner/repo IDs default from gh api (required for GitHub immutable OIDC sub)." >&2
  exit 1
}

GITHUB_REPO="${GITHUB_REPOSITORY:-}"
ROLE_NAME="${AWS_ROLE_NAME:-gha-gpg-kms-release}"
FUNCTION="${KMSPGP_LAMBDA_FUNCTION_NAME:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) [[ $# -ge 2 ]] || usage; GITHUB_REPO="$2"; shift 2 ;;
    --role-name) [[ $# -ge 2 ]] || usage; ROLE_NAME="$2"; shift 2 ;;
    --function) [[ $# -ge 2 ]] || usage; FUNCTION="$2"; shift 2 ;;
    --owner-id) [[ $# -ge 2 ]] || usage; GITHUB_OWNER_ID="$2"; shift 2 ;;
    --repo-id) [[ $# -ge 2 ]] || usage; GITHUB_REPO_ID="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

require_cmd python3
init_aws
require_account
resolve_github_repo
resolve_github_ids
GITHUB_OIDC_SUB="repo:${GITHUB_OWNER}@${GITHUB_OWNER_ID}/${GITHUB_REPO_NAME}@${GITHUB_REPO_ID}:environment:release"

if [[ ! -f "$TRUST_TEMPLATE" || ! -f "$PERMS_TEMPLATE" ]]; then
  echo "Missing policy templates next to this script." >&2
  exit 1
fi

if [[ -z "$FUNCTION" ]]; then
  echo "KMSPGP_LAMBDA_FUNCTION_NAME is not set. Source kmslambda/config.sh or pass --function." >&2
  exit 1
fi

LAMBDA_FUNCTION_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION}"
OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${GITHUB_OIDC_HOST}"

echo "GitHub Actions OIDC role:" >&2
echo "  profile:  ${PROFILE:-<default>}" >&2
echo "  repo:     $GITHUB_REPO" >&2
echo "  sub:      $GITHUB_OIDC_SUB" >&2
echo "  role:     $ROLE_NAME" >&2
echo "  region:   $REGION" >&2
echo "  function: $FUNCTION" >&2
echo >&2

existing_provider="$(aws_cli iam list-open-id-connect-providers \
  --query "OpenIDConnectProviderList[?ends_with(Arn, '/${GITHUB_OIDC_HOST}')].Arn | [0]" \
  --output text)"
if [[ -z "$existing_provider" || "$existing_provider" == "None" || "$existing_provider" == "null" ]]; then
  echo "Creating GitHub OIDC identity provider (account-wide)." >&2
  aws_cli iam create-open-id-connect-provider \
    --url "$GITHUB_OIDC_URL" \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list "${GITHUB_OIDC_THUMBPRINTS[@]}" \
    >/dev/null
else
  echo "GitHub OIDC identity provider already exists; leaving it in place." >&2
  OIDC_PROVIDER_ARN="$existing_provider"
fi

mkdir -p "$LOCAL_DIR"
TRUST_OUT="$LOCAL_DIR/trust-policy.applied.json"
PERMS_OUT="$LOCAL_DIR/permissions-policy.applied.json"

python3 - "$TRUST_TEMPLATE" "$TRUST_OUT" "$OIDC_PROVIDER_ARN" \
  "$GITHUB_OWNER" "$GITHUB_OWNER_ID" "$GITHUB_REPO_NAME" "$GITHUB_REPO_ID" <<'PY'
import pathlib, sys
src, dst, oidc, owner, owner_id, name, repo_id = sys.argv[1:8]
text = pathlib.Path(src).read_text()
text = (
    text.replace("__OIDC_PROVIDER_ARN__", oidc)
    .replace("__GITHUB_OWNER_ID__", owner_id)
    .replace("__GITHUB_REPO_ID__", repo_id)
    .replace("__GITHUB_OWNER__", owner)
    .replace("__GITHUB_REPO_NAME__", name)
)
pathlib.Path(dst).write_text(text)
PY

python3 - "$PERMS_TEMPLATE" "$PERMS_OUT" "$LAMBDA_FUNCTION_ARN" <<'PY'
import pathlib, sys
src, dst, arn = sys.argv[1], sys.argv[2], sys.argv[3]
text = pathlib.Path(src).read_text().replace("__LAMBDA_FUNCTION_ARN__", arn)
pathlib.Path(dst).write_text(text)
PY

if aws_cli iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  echo "Updating assume-role policy on existing role." >&2
  aws_cli iam update-assume-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-document "file://$TRUST_OUT" >/dev/null
else
  echo "Creating IAM role." >&2
  aws_cli iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TRUST_OUT" \
    --description "GitHub Actions OIDC role for kmslambda-signed releases" \
    --tags "Key=project,Value=gpg-kms" "Key=purpose,Value=github-actions-release" \
    >/dev/null
fi

aws_cli iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$INLINE_POLICY_NAME" \
  --policy-document "file://$PERMS_OUT" >/dev/null

ROLE_ARN="$(aws_cli iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)"

cat > "$LOCAL_DIR/role.env" <<EOF
export AWS_ROLE_NAME=$(printf '%q' "$ROLE_NAME")
export AWS_ROLE_ARN=$(printf '%q' "$ROLE_ARN")
export AWS_REGION=$(printf '%q' "$REGION")
export KMSPGP_LAMBDA_FUNCTION_NAME=$(printf '%q' "$FUNCTION")
EOF

echo "Wrote filled policies and role.env under $LOCAL_DIR (gitignored)." >&2
echo >&2

cat <<EOF
export AWS_ROLE_NAME=$(printf '%q' "$ROLE_NAME")
export AWS_ROLE_ARN=$(printf '%q' "$ROLE_ARN")
export AWS_REGION=$(printf '%q' "$REGION")
export KMSPGP_LAMBDA_FUNCTION_NAME=$(printf '%q' "$FUNCTION")
EOF

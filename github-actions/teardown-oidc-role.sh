#!/usr/bin/env bash
# Delete the GitHub Actions OIDC IAM role created by setup-oidc-role.sh.
# Leaves the account-level GitHub OIDC provider in place (it may be shared).
# Honors AWS_PROFILE. Usage: teardown-oidc-role.sh [--role-name NAME]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

INLINE_POLICY_NAME="invoke-kmslambda"

usage() {
  echo "Usage: $0 [--role-name NAME]" >&2
  echo "Env: AWS_PROFILE, AWS_ROLE_NAME, AWS_REGION" >&2
  echo "Default role name: gha-gpg-kms-release" >&2
  exit 1
}

ROLE_NAME="${AWS_ROLE_NAME:-gha-gpg-kms-release}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role-name) [[ $# -ge 2 ]] || usage; ROLE_NAME="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ -f "$LOCAL_DIR/role.env" ]]; then
  # shellcheck source=/dev/null
  source "$LOCAL_DIR/role.env"
  ROLE_NAME="${AWS_ROLE_NAME:-$ROLE_NAME}"
fi

init_aws

if ! aws_cli iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  echo "IAM role $ROLE_NAME does not exist." >&2
  exit 0
fi

echo "Deleting IAM role $ROLE_NAME (OIDC provider is left in place)." >&2
echo "  profile: ${PROFILE:-<default>}" >&2
echo "  region:  $REGION" >&2

if aws_cli iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$INLINE_POLICY_NAME" >/dev/null 2>&1; then
  aws_cli iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$INLINE_POLICY_NAME"
fi

aws_cli iam delete-role --role-name "$ROLE_NAME"
rm -f "$LOCAL_DIR/role.env" "$LOCAL_DIR/trust-policy.applied.json" "$LOCAL_DIR/permissions-policy.applied.json"

echo "Deleted role $ROLE_NAME." >&2

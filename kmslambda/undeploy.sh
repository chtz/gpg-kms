#!/usr/bin/env bash
# Undeploy Terraform-managed resources. Keeps the S3 state bucket and SSM HMAC param.
# The KMS signing key is scheduled for deletion (7-day window); the alias is removed
# immediately so ./deploy.sh can recreate a new key and the rest of the stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws
if [[ ! -f "$KMSLAMBDA_DIR/dist/index.js" ]]; then
  echo "Lambda bundle missing; building so Terraform can destroy."
  echo
  build_lambda
fi

echo "Undeploying Terraform resources with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo "  backend: $BACKEND_HCL"
echo "Kept: S3 state bucket $STATE_BUCKET"
echo "Kept: SSM parameter $APPROVAL_HMAC_PARAM_NAME"
echo

terraform_init
ensure_identity_tfvars_for_destroy
tf destroy -input=false -auto-approve

rm -f "$TFPLAN"

echo
echo "Removed Lambda, API Gateway, DynamoDB, SNS, IAM, and the KMS alias."
echo "KMS signing key is pending deletion (7 days). Re-deploy creates a new key."
echo
echo "Re-deploy:"
echo "  ./deploy.sh --user-name 'Release Signing' --user-email 'security@example.com'"
echo "  ./approvers.sh add you@example.com"

#!/usr/bin/env bash
# Destroy Terraform-managed resources. Keeps the S3 state bucket and SSM HMAC param.
# The KMS signing key is scheduled for deletion (7-day window); the alias is removed
# immediately so ./05 + ./06 can recreate a new key and the rest of the stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws
require_lambda_build

echo "Destroying Terraform resources with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo "  backend: $BACKEND_HCL"
echo "Kept: S3 state bucket $STATE_BUCKET"
echo "Kept: SSM parameter $APPROVAL_HMAC_PARAM_NAME"
echo

terraform_init
tf destroy -input=false -auto-approve

rm -f "$TFPLAN"

echo
echo "Destroyed Lambda, API Gateway, DynamoDB, SNS, IAM, and the KMS alias."
echo "KMS signing key is pending deletion (7 days). Re-deploy creates a new key."
echo
echo "Re-deploy:"
echo "  ./04_build.sh"
echo "  ./05_terraform_plan.sh"
echo "  ./06_terraform_apply.sh"
echo "  ./07_subscribe_approver.sh you@example.com"

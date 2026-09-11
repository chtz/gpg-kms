#!/usr/bin/env bash
# terraform init (S3 backend from infra/backend.hcl) and plan to infra/tfplan.
# Uses the current AWS_PROFILE and the region already configured for the AWS CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws
require_lambda_build

echo "Planning with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo "  backend: $BACKEND_HCL"
echo

terraform_init
tf plan -input=false -out=tfplan

echo
echo "Wrote $TFPLAN"
echo
echo "Next:"
echo "  ./06_terraform_apply.sh"

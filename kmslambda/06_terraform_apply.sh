#!/usr/bin/env bash
# Apply the plan written by 05_terraform_plan.sh.
# Uses the current AWS_PROFILE and the region already configured for the AWS CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws
require_tfplan

echo "Applying plan with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo "  plan:    $TFPLAN"
echo

tf apply -input=false tfplan

echo
echo "Deployed. Terraform outputs:"
tf output
echo
echo "Ready to test:"
echo "  ./07_subscribe_approver.sh you@example.com"

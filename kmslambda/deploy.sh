#!/usr/bin/env bash
# Deploy the approval-gated signing service.
# Usage: deploy.sh [--plan] [--user-name NAME] [--user-email EMAIL]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 [--plan] [--user-name NAME] [--user-email EMAIL]" >&2
  echo "First deploy requires --user-name and --user-email (or KMSPGP_USER_NAME / KMSPGP_USER_EMAIL)." >&2
  echo "Later deploys reuse $TFVARS (gitignored)." >&2
  exit 1
}

PLAN_ONLY=0
USER_NAME="${KMSPGP_USER_NAME:-}"
USER_EMAIL="${KMSPGP_USER_EMAIL:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_ONLY=1; shift ;;
    --user-name) [[ $# -ge 2 ]] || usage; USER_NAME="$2"; shift 2 ;;
    --user-email) [[ $# -ge 2 ]] || usage; USER_EMAIL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

init_aws

echo "Deploying kmslambda with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo

ensure_hmac_secret
ensure_state_bucket

echo "Planning with:"
echo "  backend: $BACKEND_HCL"
echo

terraform_init
resolve_openpgp_identity
build_lambda
require_lambda_build

tf plan -input=false -out=tfplan

echo
echo "Wrote $TFPLAN"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo
  echo "Plan only. Apply with:"
  echo "  ./deploy.sh"
  exit 0
fi

echo
tf apply -input=false tfplan

echo
echo "Deployed. Terraform outputs:"
tf output
echo
echo "Next:"
echo "  ./approvers.sh add you@example.com"
echo "  # confirm the AWS SNS email, then"
echo "  ./config.sh > envfile && . ./envfile"

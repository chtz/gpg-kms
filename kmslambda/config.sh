#!/usr/bin/env bash
# Approval-service config. Prints sourceable export lines to stdout.
# Usage: ./config.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

if [[ $# -gt 0 ]]; then
  echo "Usage: $0" >&2
  echo "Redirect stdout to a file and source it, e.g. $0 > env && . ./env" >&2
  exit 1
fi

init_aws

API_BASE_URL="$(tf_output api_base_url)"
LAMBDA_FUNCTION_NAME="$(tf_output lambda_function_name)"

cat <<EOF
export AWS_REGION=$(printf '%q' "$REGION")
export KMSPGP_LAMBDA_FUNCTION_NAME=$(printf '%q' "$LAMBDA_FUNCTION_NAME")
export KMSPGP_LAMBDA_API_BASE_URL=$(printf '%q' "$API_BASE_URL")
EOF

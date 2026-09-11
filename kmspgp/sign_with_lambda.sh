#!/usr/bin/env bash
# Sign testartifact.txt via a deployed kmslambda (human approval), producing an
# OpenPGP detached signature. Does not use ~/.gnupg or the direct-KMS test key.
# Writes testartifact.txt.lambda.asc (not testartifact.txt.asc).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

KMSLAMBDA_DIR="${KMSLAMBDA_DIR:-$SCRIPT_DIR/../kmslambda}"
# shellcheck source=../kmslambda/common.sh
source "$KMSLAMBDA_DIR/common.sh"

ARTIFACT="${1:-testartifact.txt}"
SIGNATURE="${ARTIFACT}.lambda.asc"

init_aws
require_jar

if [[ ! -f "$ARTIFACT" ]]; then
  echo "File to sign not found: $ARTIFACT" >&2
  exit 1
fi

export KMSPGP_LAMBDA_FUNCTION_NAME="$(tf_output lambda_function_name)"
export KMSPGP_LAMBDA_API_BASE_URL="$(tf_output api_base_url)"

echo "Signing via kmslambda (approve the SNS link while this waits):"
echo "  profile:   ${PROFILE:-<default>}"
echo "  region:    $REGION"
echo "  function:  $KMSPGP_LAMBDA_FUNCTION_NAME"
echo "  api:       $KMSPGP_LAMBDA_API_BASE_URL"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo

kmspgp lambda-sign \
  --artifact "$(basename "$ARTIFACT")" \
  --version test \
  --environment test \
  < "$ARTIFACT" > "$SIGNATURE"

echo
echo "Signed with approval-gated kmslambda:"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo
echo "Verify with:"
echo "  ./verify_with_lambda.sh $ARTIFACT"

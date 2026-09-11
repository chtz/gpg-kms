#!/usr/bin/env bash
# Create the SSM SecureString used to HMAC-sign approval and poll tokens.
# Uses the current AWS_PROFILE and the region already configured for the AWS CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws

echo "Creating HMAC secret with:"
echo "  profile:   ${PROFILE:-<default>}"
echo "  region:    $REGION"
echo "  parameter: $APPROVAL_HMAC_PARAM_NAME"
echo

param_exists=0
if aws_ssm get-parameter --name "$APPROVAL_HMAC_PARAM_NAME" >/dev/null 2>&1; then
  param_exists=1
fi

if [[ "$param_exists" -eq 1 && "${OVERWRITE:-}" != "1" ]]; then
  echo "Parameter already exists; leaving it unchanged."
  echo "Set OVERWRITE=1 to replace the value (invalidates outstanding tokens)."
  echo
else
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate the secret but was not found on PATH." >&2
    exit 1
  fi

  SECRET_HEX="$(openssl rand -hex 32)"
  put_args=(
    put-parameter
    --name "$APPROVAL_HMAC_PARAM_NAME"
    --type SecureString
    --value "$SECRET_HEX"
  )
  if [[ "$param_exists" -eq 1 ]]; then
    put_args+=(--overwrite)
  fi
  aws_ssm "${put_args[@]}" >/dev/null
  if [[ "$param_exists" -eq 1 ]]; then
    echo "Replaced SecureString parameter."
  else
    echo "Created SecureString parameter."
  fi
  echo
fi

echo "Terraform defaults to this SSM name; override with TF_VAR_approval_hmac_param_name if you changed it."
echo
echo "Next:"
echo "  ./02_create_state_bucket.sh"

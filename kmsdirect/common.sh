#!/usr/bin/env bash
# Shared helpers for kmsdirect. Source this file; do not execute.

KMSDIRECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALIAS_NAME="${KMSPGP_KMS_ALIAS:-alias/kmspgp-signing}"

require_aws() {
  if ! command -v aws >/dev/null 2>&1; then
    echo "aws CLI is required but was not found on PATH." >&2
    exit 1
  fi
}

init_aws() {
  require_aws
  PROFILE="${AWS_PROFILE:-}"
  REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

  if [[ -z "$REGION" ]]; then
    if [[ -n "$PROFILE" ]]; then
      REGION="$(aws configure get region --profile "$PROFILE" || true)"
    else
      REGION="$(aws configure get region || true)"
    fi
  fi

  if [[ -z "$REGION" ]]; then
    echo "Could not determine AWS region. Set AWS_REGION or configure a region for the current profile." >&2
    exit 1
  fi
}

aws_kms() {
  local -a extra=()
  extra+=(--region "$REGION")
  if [[ -n "${PROFILE:-}" ]]; then
    extra+=(--profile "$PROFILE")
  fi
  aws kms "$@" "${extra[@]}"
}

lookup_signing_key_id() {
  local key_id
  if ! key_id="$(aws_kms describe-key --key-id "$ALIAS_NAME" --query 'KeyMetadata.KeyId' --output text 2>/dev/null)" \
     || [[ -z "$key_id" || "$key_id" == "None" ]]; then
    echo "No KMS key found for $ALIAS_NAME. Run ./deploy.sh first." >&2
    return 1
  fi
  printf '%s\n' "$key_id"
}

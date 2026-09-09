#!/usr/bin/env bash
# Shared helpers for kmspgp test-key scripts. Source this file; do not execute.

ALIAS_NAME="alias/kmspgp-test-signing"
DEFAULT_GPG_HOME_NAME="gpg_temp"

require_aws() {
  if ! command -v aws >/dev/null 2>&1; then
    echo "aws CLI is required but was not found on PATH." >&2
    exit 1
  fi
}

require_java() {
  if ! command -v java >/dev/null 2>&1; then
    echo "java is required but was not found on PATH." >&2
    exit 1
  fi
}

require_jar() {
  require_java
  JAR="${KMSPGP_JAR:-$SCRIPT_DIR/target/kmspgp.jar}"
  if [[ ! -f "$JAR" ]]; then
    echo "kmspgp jar not found: $JAR" >&2
    echo "Run mvn clean install first." >&2
    exit 1
  fi
}

kmspgp() {
  require_jar
  java -jar "$JAR" "$@"
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

describe_test_key() {
  aws_kms describe-key --key-id "$ALIAS_NAME" "$@"
}

lookup_test_key_id() {
  local key_id
  if ! key_id="$(describe_test_key --query 'KeyMetadata.KeyId' --output text 2>/dev/null)" \
     || [[ -z "$key_id" || "$key_id" == "None" ]]; then
    echo "No KMS key found for $ALIAS_NAME. Run ./create_test_key.sh first." >&2
    return 1
  fi
  printf '%s\n' "$key_id"
}

require_isolated_gpg_home() {
  local gpg_home="$1"
  if [[ "$gpg_home" == "$HOME/.gnupg" || "$gpg_home" == "$HOME/.gnupg/" ]]; then
    echo "Refusing to use or clear ~/.gnupg. Set GPG_TEMP_HOME to an isolated directory." >&2
    exit 1
  fi
}

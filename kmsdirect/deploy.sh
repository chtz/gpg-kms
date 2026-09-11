#!/usr/bin/env bash
# Create or reuse a KMS ECC_NIST_P256 SIGN_VERIFY key (direct backend).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

KEY_SPEC="ECC_NIST_P256"
DESCRIPTION="Artifact signing key (KMS) for kmspgp"

init_aws

echo "Deploying direct KMS signing key:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  alias:   $ALIAS_NAME"
echo "  spec:    $KEY_SPEC (SIGN_VERIFY)"
echo

create_new_key() {
  local key_id
  key_id="$(aws_kms create-key \
    --key-usage SIGN_VERIFY \
    --key-spec "$KEY_SPEC" \
    --description "$DESCRIPTION" \
    --tags "TagKey=Purpose,TagValue=artifact-signing" "TagKey=Name,TagValue=kmspgp-signing" \
    --query 'KeyMetadata.KeyId' \
    --output text)"

  aws_kms create-alias \
    --alias-name "$ALIAS_NAME" \
    --target-key-id "$key_id" \
    >/dev/null

  aws_kms describe-key --key-id "$ALIAS_NAME" --query 'KeyMetadata.Arn' --output text
}

if key_arn="$(aws_kms describe-key --key-id "$ALIAS_NAME" --query 'KeyMetadata.Arn' --output text 2>/dev/null)" \
   && [[ -n "$key_arn" && "$key_arn" != "None" ]]; then
  key_state="$(aws_kms describe-key --key-id "$ALIAS_NAME" --query 'KeyMetadata.KeyState' --output text)"
  if [[ "$key_state" == "Enabled" ]]; then
    echo "Key already exists:"
  else
    echo "Alias $ALIAS_NAME points to a key in state $key_state; creating a new key."
    aws_kms delete-alias --alias-name "$ALIAS_NAME"
    key_arn="$(create_new_key)"
    echo "Created key:"
  fi
else
  key_arn="$(create_new_key)"
  echo "Created key:"
fi

echo "  alias: $ALIAS_NAME"
echo "  arn:   $key_arn"
echo
echo "Next:"
echo "  ./config.sh > envfile && . ./envfile"

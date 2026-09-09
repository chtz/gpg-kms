#!/usr/bin/env bash
# Create a KMS asymmetric SIGN_VERIFY test key for kmspgp.
# Uses the current AWS_PROFILE and the region already configured for the AWS CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

KEY_SPEC="ECC_NIST_P256"
DESCRIPTION="kmspgp test signing key (safe to delete)"

init_aws

echo "Creating kmspgp test key with:"
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
    --tags "TagKey=Purpose,TagValue=kmspgp-test" "TagKey=Name,TagValue=kmspgp-test-signing" \
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
echo "kmspgp uses the AWS SDK default credential and region chain."
if [[ -n "$PROFILE" ]]; then
  echo "  AWS_PROFILE=$PROFILE  (region $REGION from this profile unless AWS_REGION is set)"
else
  echo "  region $REGION from the default profile unless AWS_REGION is set"
fi
echo
echo "Try it:"
echo "  mvn clean install"
echo "  ./export_test_key.sh"
echo "  ./import_test_key.sh"
echo "  ./sign_with_test_key.sh"
echo "  ./verify_with_test_key.sh"
echo "  ./delete_test_key.sh"

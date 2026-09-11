#!/usr/bin/env bash
# Delete the direct-KMS signing alias and schedule the key for deletion.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

PENDING_WINDOW_DAYS="${KMS_PENDING_WINDOW_DAYS:-7}"

init_aws

if ! [[ "$PENDING_WINDOW_DAYS" =~ ^[0-9]+$ ]] || (( PENDING_WINDOW_DAYS < 7 || PENDING_WINDOW_DAYS > 30 )); then
  echo "KMS pending deletion window must be an integer between 7 and 30 days." >&2
  exit 1
fi

if ! key_id="$(lookup_signing_key_id)"; then
  exit 1
fi

key_arn="$(aws_kms describe-key --key-id "$key_id" --query 'KeyMetadata.Arn' --output text)"
key_state="$(aws_kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyState' --output text)"

echo "Undeploying direct KMS signing key:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  alias:   $ALIAS_NAME"
echo "  key:     $key_id"
echo "  arn:     $key_arn"
echo "  state:   $key_state"
echo "  window:  ${PENDING_WINDOW_DAYS} days"
echo

aws_kms delete-alias --alias-name "$ALIAS_NAME"

if [[ "$key_state" == "PendingDeletion" ]]; then
  echo "Alias deleted. Key is already pending deletion."
else
  deletion_date="$(aws_kms schedule-key-deletion \
    --key-id "$key_id" \
    --pending-window-in-days "$PENDING_WINDOW_DAYS" \
    --query 'DeletionDate' \
    --output text)"
  echo "Alias deleted and key scheduled for deletion on $deletion_date."
fi

echo
echo "Deploy again with:"
echo "  ./deploy.sh"

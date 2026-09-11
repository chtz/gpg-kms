#!/usr/bin/env bash
# Add or list SNS approvers for the signing service.
# Usage: approvers.sh add <email>
#        approvers.sh list
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 add <email>" >&2
  echo "       $0 list" >&2
  echo "Or: $0 add   with APPROVER_EMAIL set." >&2
  exit 1
}

CMD="${1:-}"
case "$CMD" in
  add|list) ;;
  *) usage ;;
esac
shift || true

init_aws
TOPIC_ARN="$(tf_output sns_topic_arn)"

add_approver() {
  local email="${1:-${APPROVER_EMAIL:-}}"
  if [[ -z "$email" || "$email" != *@*.* ]]; then
    usage
  fi

  echo "Subscribing approver with:"
  echo "  profile: ${PROFILE:-<default>}"
  echo "  region:  $REGION"
  echo "  topic:   $TOPIC_ARN"
  echo "  email:   $email"
  echo

  local existing_arn
  existing_arn="$(aws_cli sns list-subscriptions-by-topic \
    --topic-arn "$TOPIC_ARN" \
    --query "Subscriptions[?Protocol=='email' && Endpoint=='${email}'].SubscriptionArn | [0]" \
    --output text)"

  if [[ -n "$existing_arn" && "$existing_arn" != "None" && "$existing_arn" != "null" ]]; then
    if [[ "$existing_arn" == "PendingConfirmation" ]]; then
      echo "Already subscribed but still pending confirmation."
      echo "Check inbox (and spam) for AWS Notification - Subscription Confirmation."
    else
      echo "Already subscribed and confirmed:"
      echo "  $existing_arn"
    fi
  else
    local sub_arn
    sub_arn="$(aws_cli sns subscribe \
      --topic-arn "$TOPIC_ARN" \
      --protocol email \
      --notification-endpoint "$email" \
      --return-subscription-arn \
      --query SubscriptionArn \
      --output text)"
    echo "Subscription requested: $sub_arn"
    echo "Confirm the email from AWS before creating a signing request."
  fi

  echo
  echo "Next (after confirming the email):"
  echo "  ./config.sh > envfile && . ./envfile"
  echo "  ../dist/lambda-sign.sh --function \"\$KMSPGP_LAMBDA_FUNCTION_NAME\" --api \"\$KMSPGP_LAMBDA_API_BASE_URL\" /path/to/artifact"
}

list_approvers() {
  echo "Approvers on $TOPIC_ARN"
  echo "  profile: ${PROFILE:-<default>}"
  echo "  region:  $REGION"
  echo

  aws_cli sns list-subscriptions-by-topic \
    --topic-arn "$TOPIC_ARN" \
    --query "Subscriptions[].[Protocol,Endpoint,SubscriptionArn]" \
    --output text | awk -F'\t' '{
      status = ($3 == "PendingConfirmation") ? "pending" : "confirmed"
      printf "  %-8s  %s  %s\n", $1, $2, status
    }'

  echo
  echo "Email subscriptions stay inactive until the AWS confirmation link is clicked."
}

case "$CMD" in
  add) add_approver "${1:-}" ;;
  list) list_approvers ;;
  *) usage ;;
esac

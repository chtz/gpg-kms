#!/usr/bin/env bash
# Subscribe an email address to the SNS approvals topic.
# AWS sends a confirmation mail; the subscription is inactive until that link is clicked.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

EMAIL="${1:-${APPROVER_EMAIL:-}}"
if [[ -z "$EMAIL" || "$EMAIL" != *@*.* ]]; then
  echo "Usage: $0 <email>" >&2
  echo "Or set APPROVER_EMAIL." >&2
  exit 1
fi

init_aws
TOPIC_ARN="$(tf_output sns_topic_arn)"

echo "Subscribing approver with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  topic:   $TOPIC_ARN"
echo "  email:   $EMAIL"
echo

existing_arn="$(aws_cli sns list-subscriptions-by-topic \
  --topic-arn "$TOPIC_ARN" \
  --query "Subscriptions[?Protocol=='email' && Endpoint=='${EMAIL}'].SubscriptionArn | [0]" \
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
  sub_arn="$(aws_cli sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol email \
    --notification-endpoint "$EMAIL" \
    --return-subscription-arn \
    --query SubscriptionArn \
    --output text)"
  echo "Subscription requested: $sub_arn"
  echo "Confirm the email from AWS before creating a signing request."
fi

echo
echo "Next (after confirming the email):"
echo "  ./08_create_signing_request.sh"

#!/usr/bin/env bash
# Create the S3 bucket used for Terraform remote state, then write infra/backend.hcl.
# Uses the current AWS_PROFILE and the region already configured for the AWS CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

init_aws

echo "Preparing Terraform state bucket with:"
echo "  profile: ${PROFILE:-<default>}"
echo "  region:  $REGION"
echo "  account: $ACCOUNT_ID"
echo "  bucket:  $STATE_BUCKET"
echo

if aws_cli s3api head-bucket --bucket "$STATE_BUCKET" >/dev/null 2>&1; then
  echo "Bucket already exists; leaving it in place."
else
  if [[ "$REGION" == "us-east-1" ]]; then
    aws_cli s3api create-bucket --bucket "$STATE_BUCKET" >/dev/null
  else
    aws_cli s3api create-bucket \
      --bucket "$STATE_BUCKET" \
      --create-bucket-configuration LocationConstraint="$REGION" \
      >/dev/null
  fi
  echo "Created bucket."
fi

aws_cli s3api put-bucket-versioning \
  --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled >/dev/null

aws_cli s3api put-public-access-block \
  --bucket "$STATE_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  >/dev/null

aws_cli s3api put-bucket-encryption \
  --bucket "$STATE_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}' \
  >/dev/null

write_backend_hcl
echo "Wrote $BACKEND_HCL"
echo
echo "Next:"
echo "  ./03_npm_install.sh"

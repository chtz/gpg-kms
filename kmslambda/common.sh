#!/usr/bin/env bash
# Shared helpers for kmslambda deploy/test scripts. Source this file; do not execute.

KMSLAMBDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$KMSLAMBDA_DIR/infra"
BACKEND_HCL="$INFRA_DIR/backend.hcl"
TFPLAN="$INFRA_DIR/tfplan"
STATE_KEY="kmslambda/terraform.tfstate"
APPROVAL_HMAC_PARAM_NAME="${APPROVAL_HMAC_PARAM_NAME:-/artifact-signing/approval-hmac}"
LAST_REQUEST_FILE="$KMSLAMBDA_DIR/last-signing-request.json"
DEFAULT_ARTIFACT="$KMSLAMBDA_DIR/testdata/artifact.txt"

require_aws() {
  if ! command -v aws >/dev/null 2>&1; then
    echo "aws CLI is required but was not found on PATH." >&2
    exit 1
  fi
}

require_terraform() {
  if ! command -v terraform >/dev/null 2>&1; then
    echo "terraform is required but was not found on PATH." >&2
    exit 1
  fi
}

require_npm() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required but was not found on PATH." >&2
    exit 1
  fi
}

require_node() {
  if ! command -v node >/dev/null 2>&1; then
    echo "node is required but was not found on PATH." >&2
    exit 1
  fi
}

npm_ci() {
  require_npm
  if [[ ! -f "$KMSLAMBDA_DIR/package-lock.json" ]]; then
    echo "Missing package-lock.json. After clone it must be in git so npm ci can run." >&2
    exit 1
  fi
  echo "Installing npm dependencies in $KMSLAMBDA_DIR"
  (cd "$KMSLAMBDA_DIR" && npm ci)
}

ensure_node_modules() {
  if [[ ! -d "$KMSLAMBDA_DIR/node_modules" ]]; then
    echo "node_modules missing; running npm ci"
    echo
    npm_ci
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

  ACCOUNT_ID="$(aws_cli sts get-caller-identity --query Account --output text)"
  if [[ -z "$ACCOUNT_ID" || "$ACCOUNT_ID" == "None" ]]; then
    echo "Could not determine AWS account id. Check AWS_PROFILE and SSO login." >&2
    exit 1
  fi
  STATE_BUCKET="kmslambda-tfstate-${ACCOUNT_ID}-${REGION}"
}

aws_cli() {
  local -a extra=()
  extra+=(--region "$REGION")
  if [[ -n "${PROFILE:-}" ]]; then
    extra+=(--profile "$PROFILE")
  fi
  aws "${extra[@]}" "$@"
}

aws_ssm() {
  aws_cli ssm "$@"
}

write_backend_hcl() {
  mkdir -p "$INFRA_DIR"
  cat > "$BACKEND_HCL" <<EOF
bucket  = "${STATE_BUCKET}"
key     = "${STATE_KEY}"
region  = "${REGION}"
encrypt = true
EOF
}

require_backend_hcl() {
  if [[ ! -f "$BACKEND_HCL" ]]; then
    echo "Missing $BACKEND_HCL. Run ./02_create_state_bucket.sh first." >&2
    exit 1
  fi
}

require_lambda_build() {
  if [[ ! -f "$KMSLAMBDA_DIR/dist/index.js" ]]; then
    echo "Missing dist/index.js. Run ./04_build.sh first." >&2
    exit 1
  fi
}

require_tfplan() {
  if [[ ! -f "$TFPLAN" ]]; then
    echo "Missing $TFPLAN. Run ./05_terraform_plan.sh first." >&2
    exit 1
  fi
}

# Terraform's AWS SDK (S3 backend) does not understand SSO profiles that use
# sso_session without sso_start_url/sso_region on the profile. The CLI does.
# Export temporary keys from the CLI session and drop AWS_PROFILE so Terraform
# uses the env credentials instead of parsing ~/.aws/config.
export_cli_credentials() {
  local creds
  local -a extra=()
  if [[ -n "${PROFILE:-}" ]]; then
    extra+=(--profile "$PROFILE")
  fi
  if ! creds="$(aws "${extra[@]}" configure export-credentials --format env)"; then
    echo "Failed to export credentials from the AWS CLI. Run: aws sso login${PROFILE:+ --profile $PROFILE}" >&2
    exit 1
  fi
  eval "$creds"
  export AWS_REGION="$REGION"
  export AWS_DEFAULT_REGION="$REGION"
  unset AWS_PROFILE AWS_DEFAULT_PROFILE
}

tf() {
  require_terraform
  if [[ -z "${_KMSLAMBDA_TF_CREDS:-}" ]]; then
    export_cli_credentials
    _KMSLAMBDA_TF_CREDS=1
  fi
  terraform -chdir="$INFRA_DIR" "$@"
}

terraform_init() {
  require_backend_hcl
  tf init -input=false -reconfigure -backend-config=backend.hcl
}

tf_output() {
  local name="$1"
  local value
  if ! value="$(tf output -raw "$name" 2>/dev/null)" || [[ -z "$value" ]]; then
    echo "Could not read Terraform output '$name'. Run ./06_terraform_apply.sh first." >&2
    exit 1
  fi
  printf '%s\n' "$value"
}

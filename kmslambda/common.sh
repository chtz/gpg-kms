#!/usr/bin/env bash
# Shared helpers for kmslambda deploy/test scripts. Source this file; do not execute.

KMSLAMBDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$KMSLAMBDA_DIR/infra"
BACKEND_HCL="$INFRA_DIR/backend.hcl"
TFVARS="$INFRA_DIR/terraform.tfvars"
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
    echo "Missing $BACKEND_HCL. Run ./deploy.sh first." >&2
    exit 1
  fi
}

require_lambda_build() {
  if [[ ! -f "$KMSLAMBDA_DIR/dist/index.js" ]]; then
    echo "Missing dist/index.js. Run ./deploy.sh first." >&2
    exit 1
  fi
}

require_tfplan() {
  if [[ ! -f "$TFPLAN" ]]; then
    echo "Missing $TFPLAN. Run ./deploy.sh --plan first." >&2
    exit 1
  fi
}

ensure_hmac_secret() {
  echo "HMAC secret:"
  echo "  parameter: $APPROVAL_HMAC_PARAM_NAME"
  echo

  local param_exists=0
  if aws_ssm get-parameter --name "$APPROVAL_HMAC_PARAM_NAME" >/dev/null 2>&1; then
    param_exists=1
  fi

  if [[ "$param_exists" -eq 1 && "${OVERWRITE:-}" != "1" ]]; then
    echo "Parameter already exists; leaving it unchanged."
    echo "Set OVERWRITE=1 to replace the value (invalidates outstanding tokens)."
    echo
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate the secret but was not found on PATH." >&2
    exit 1
  fi

  local secret_hex
  secret_hex="$(openssl rand -hex 32)"
  local -a put_args=(
    put-parameter
    --name "$APPROVAL_HMAC_PARAM_NAME"
    --type SecureString
    --value "$secret_hex"
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
}

ensure_state_bucket() {
  echo "Terraform state bucket:"
  echo "  bucket: $STATE_BUCKET"
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
}

build_lambda() {
  ensure_node_modules
  echo "Building Lambda bundle in $KMSLAMBDA_DIR"
  echo
  (cd "$KMSLAMBDA_DIR" && npm run build)
  echo
  echo "Built dist/index.js"
  echo
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
    echo "Could not read Terraform output '$name'. Run ./deploy.sh first." >&2
    exit 1
  fi
  printf '%s\n' "$value"
}

tf_output_optional() {
  local name="$1"
  tf output -raw "$name" 2>/dev/null || true
}

hcl_quote() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

read_tfvars_string() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  awk -v key="$key" '
    $1 == key && $2 == "=" {
      v = $0
      sub(/^[^=]*=[[:space:]]*/, "", v)
      sub(/[[:space:]]*$/, "", v)
      if (v ~ /^".*"$/) {
        v = substr(v, 2, length(v) - 2)
        gsub(/\\"/, "\"", v)
        gsub(/\\\\/, "\\", v)
      }
      print v
    }
  ' "$file" | tail -n1
}

write_identity_tfvars() {
  local name="$1"
  local email="$2"
  cat > "$TFVARS" <<EOF
# Generated by deploy.sh. Do not commit. Redeploy reuses these values.
openpgp_user_name  = $(hcl_quote "$name")
openpgp_user_email = $(hcl_quote "$email")
EOF
}

identity_usage() {
  echo "OpenPGP user id is required on first deploy:" >&2
  echo "  ./deploy.sh --user-name 'Release Signing' --user-email 'security@example.com'" >&2
  echo "  or set KMSPGP_USER_NAME and KMSPGP_USER_EMAIL" >&2
  echo "Later deploys reuse $TFVARS (gitignored)." >&2
}

validate_identity() {
  local name="$1"
  local email="$2"
  if [[ -z "$name" ]]; then
    echo "error: OpenPGP user name is empty" >&2
    identity_usage
    return 1
  fi
  if [[ -z "$email" || "$email" != *@*.* || "$email" == *@*@* || "$email" == *[[:space:]]* ]]; then
    echo "error: OpenPGP user email must be a simple address (got: ${email:-<empty>})" >&2
    identity_usage
    return 1
  fi
}

# Resolve name/email from flags/env (already in USER_NAME/USER_EMAIL), then
# gitignored tfvars, then Terraform state. Writes tfvars when resolution succeeds.
resolve_openpgp_identity() {
  local from="flags/env"
  local existing_name existing_email

  if [[ -z "${USER_NAME:-}" ]]; then
    USER_NAME="$(read_tfvars_string openpgp_user_name "$TFVARS")"
    from="tfvars"
  fi
  if [[ -z "${USER_EMAIL:-}" ]]; then
    USER_EMAIL="$(read_tfvars_string openpgp_user_email "$TFVARS")"
    from="tfvars"
  fi

  if [[ -z "${USER_NAME:-}" || -z "${USER_EMAIL:-}" ]]; then
    local state_name state_email
    state_name="$(tf_output_optional openpgp_user_name)"
    state_email="$(tf_output_optional openpgp_user_email)"
    USER_NAME="${USER_NAME:-$state_name}"
    USER_EMAIL="${USER_EMAIL:-$state_email}"
    if [[ -n "${USER_NAME:-}" && -n "${USER_EMAIL:-}" ]]; then
      from="terraform state"
    fi
  fi

  if [[ -z "${USER_NAME:-}" || -z "${USER_EMAIL:-}" ]]; then
    identity_usage
    return 1
  fi

  validate_identity "$USER_NAME" "$USER_EMAIL" || return 1

  existing_name="$(read_tfvars_string openpgp_user_name "$TFVARS")"
  existing_email="$(read_tfvars_string openpgp_user_email "$TFVARS")"
  if [[ -n "$existing_name" && -n "$existing_email" &&
        ( "$existing_name" != "$USER_NAME" || "$existing_email" != "$USER_EMAIL" ) ]]; then
    echo "Updating OpenPGP user id (fingerprint stays the same; a new self-certification is issued):" >&2
    echo "  was: $existing_name <$existing_email>" >&2
    echo "  now: $USER_NAME <$USER_EMAIL>" >&2
    echo
  fi

  write_identity_tfvars "$USER_NAME" "$USER_EMAIL"
  echo "OpenPGP user id ($from):" >&2
  echo "  uid:    $USER_NAME <$USER_EMAIL>" >&2
  echo "  tfvars: $TFVARS" >&2
  echo
}

# Destroy still needs the required variables in the configuration.
# Recover from tfvars or state; if both are missing (pre-identity stack), use placeholders.
ensure_identity_tfvars_for_destroy() {
  USER_NAME="$(read_tfvars_string openpgp_user_name "$TFVARS")"
  USER_EMAIL="$(read_tfvars_string openpgp_user_email "$TFVARS")"
  if [[ -z "$USER_NAME" || -z "$USER_EMAIL" ]]; then
    USER_NAME="$(tf_output_optional openpgp_user_name)"
    USER_EMAIL="$(tf_output_optional openpgp_user_email)"
  fi
  if [[ -n "$USER_NAME" && -n "$USER_EMAIL" ]]; then
    write_identity_tfvars "$USER_NAME" "$USER_EMAIL"
    return 0
  fi
  echo "No OpenPGP identity in terraform.tfvars or state; using placeholders so destroy can run."
  echo
  write_identity_tfvars "undeploy" "undeploy@invalid.local"
}

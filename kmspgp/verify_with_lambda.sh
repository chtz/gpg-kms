#!/usr/bin/env bash
# Export the kmslambda OpenPGP public key and verify a signature from
# sign_with_lambda.sh in an isolated GnuPG homedir (./gpg_temp_lambda).
# Does not touch ~/.gnupg or ./gpg_temp (the direct-KMS test keyring).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

KMSLAMBDA_DIR="${KMSLAMBDA_DIR:-$SCRIPT_DIR/../kmslambda}"
# shellcheck source=../kmslambda/common.sh
source "$KMSLAMBDA_DIR/common.sh"

ARTIFACT="${1:-testartifact.txt}"
SIGNATURE="${ARTIFACT}.lambda.asc"
PUB_KEY="${2:-kmspgp-lambda-pub.asc}"
GPG_HOME="${GPG_TEMP_LAMBDA_HOME:-$PWD/gpg_temp_lambda}"

init_aws
require_jar
require_isolated_gpg_home "$GPG_HOME"

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required but was not found on PATH." >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "File to verify not found: $ARTIFACT" >&2
  exit 1
fi

if [[ ! -f "$SIGNATURE" ]]; then
  echo "Signature not found: $SIGNATURE" >&2
  echo "Run ./sign_with_lambda.sh first." >&2
  exit 1
fi

export KMSPGP_LAMBDA_FUNCTION_NAME="$(tf_output lambda_function_name)"
export KMSPGP_LAMBDA_API_BASE_URL="$(tf_output api_base_url)"

kmspgp lambda-export \
  --user-name "Test" \
  --user-email "test@example.com" \
  > "$PUB_KEY"

if [[ -e "$GPG_HOME" ]]; then
  echo "Clearing isolated GPG homedir: $GPG_HOME"
  rm -rf "$GPG_HOME"
fi
mkdir -p "$GPG_HOME"
chmod 700 "$GPG_HOME"

gpg --homedir "$GPG_HOME" --batch --import "$PUB_KEY"

echo
echo "Verifying with isolated GPG homedir:"
echo "  homedir:   $GPG_HOME"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo "  public key: $PUB_KEY"
echo

gpg --homedir "$GPG_HOME" --verify "$SIGNATURE" "$ARTIFACT"

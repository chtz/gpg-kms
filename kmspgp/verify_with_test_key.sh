#!/usr/bin/env bash
# Verify a signature created by sign_with_test_key.sh using the isolated GPG homedir.
# Does not touch ~/.gnupg.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

ARTIFACT="${1:-testartifact.txt}"
SIGNATURE="${ARTIFACT}.asc"
GPG_HOME="${GPG_TEMP_HOME:-$PWD/$DEFAULT_GPG_HOME_NAME}"

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
  echo "Run ./sign_with_test_key.sh first." >&2
  exit 1
fi

if [[ ! -d "$GPG_HOME" ]]; then
  echo "Isolated GPG homedir not found: $GPG_HOME" >&2
  echo "Run ./import_test_key.sh first." >&2
  exit 1
fi

echo "Verifying with isolated GPG homedir:"
echo "  homedir:   $GPG_HOME"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo

gpg --homedir "$GPG_HOME" --verify "$SIGNATURE" "$ARTIFACT"

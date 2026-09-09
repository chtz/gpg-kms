#!/usr/bin/env bash
# Sign an artifact with the secret key in an existing GnuPG home.
# Usage: sign.sh <signer-home> <artifact> [output.sig]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gpg-common.sh
source "$SCRIPT_DIR/gpg-common.sh"

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <signer-home> <artifact> [output.sig]" >&2
  exit 1
fi

SIGNER_HOME="$(cd "$1" && pwd)"
ARTIFACT="$2"
if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi

if [[ $# -eq 3 ]]; then
  OUTPUT="$3"
else
  OUTPUT="${ARTIFACT}.sig"
fi

FPR="$(secret_key_fingerprint "$SIGNER_HOME")"
if [[ -z "$FPR" ]]; then
  echo "error: no secret key in $SIGNER_HOME" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
gpg_unattended "$SIGNER_HOME" \
  --local-user "$FPR" \
  --detach-sign \
  --armor \
  --output "$OUTPUT" \
  "$ARTIFACT"

echo "Signed $ARTIFACT -> $OUTPUT (key $FPR)"

#!/usr/bin/env bash
# Detached OpenPGP signature via a KMS key. Jar must sit next to this script.
# Usage: kms-sign.sh --key KEY <artifact> [output.asc]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 --key KEY <artifact> [output.asc]" >&2
  echo "Env: KMSPGP_KMS_KEY" >&2
  exit 1
}

KEY="${KMSPGP_KMS_KEY:-}"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) [[ $# -ge 2 ]] || usage; KEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    --*) usage ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

require_val --key KMSPGP_KMS_KEY "$KEY"
[[ ${#POSITIONAL[@]} -ge 1 && ${#POSITIONAL[@]} -le 2 ]] || usage

ARTIFACT="${POSITIONAL[0]}"
if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  OUTPUT="${POSITIONAL[1]}"
else
  OUTPUT="${ARTIFACT}.asc"
fi

mkdir -p "$(dirname "$OUTPUT")"
echo "Signing with KMS:"
echo "  key:       $KEY"
echo "  artifact:  $ARTIFACT"
echo "  signature: $OUTPUT"
echo
kmspgp -bsau "$KEY" < "$ARTIFACT" > "$OUTPUT"
echo "Signed $ARTIFACT -> $OUTPUT"

#!/usr/bin/env bash
# Export an OpenPGP public key from a deployed kmslambda stack (Lambda invoke).
# Jar must sit next to this script.
# Usage: lambda-export.sh --function NAME --out FILE
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 --function NAME --out FILE" >&2
  echo "Env: KMSPGP_LAMBDA_FUNCTION_NAME" >&2
  echo "OpenPGP user id is bound at kmslambda deploy, not passed here." >&2
  exit 1
}

FUNCTION="${KMSPGP_LAMBDA_FUNCTION_NAME:-}"
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --function) [[ $# -ge 2 ]] || usage; FUNCTION="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

require_val --function KMSPGP_LAMBDA_FUNCTION_NAME "$FUNCTION"
if [[ -z "$OUT" ]]; then
  echo "error: --out FILE is required" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
echo "Exporting OpenPGP public key from kmslambda:" >&2
echo "  function: $FUNCTION" >&2
echo "  file:     $OUT" >&2
kmspgp lambda-export --function "$FUNCTION" > "$OUT"
echo "Wrote $OUT" >&2

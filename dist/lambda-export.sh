#!/usr/bin/env bash
# Export an OpenPGP public key from a deployed kmslambda stack.
# Jar must sit next to this script.
# Usage: lambda-export.sh --api URL --out FILE
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 --api URL --out FILE" >&2
  echo "Env: KMSPGP_LAMBDA_API_BASE_URL" >&2
  echo "OpenPGP user id is bound at kmslambda deploy, not passed here." >&2
  exit 1
}

API="${KMSPGP_LAMBDA_API_BASE_URL:-}"
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api) [[ $# -ge 2 ]] || usage; API="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

require_val --api KMSPGP_LAMBDA_API_BASE_URL "$API"
if [[ -z "$OUT" ]]; then
  echo "error: --out FILE is required" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
echo "Exporting OpenPGP public key from kmslambda:" >&2
echo "  api:  $API" >&2
echo "  file: $OUT" >&2
kmspgp lambda-export --api "$API" > "$OUT"
echo "Wrote $OUT" >&2

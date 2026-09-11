#!/usr/bin/env bash
# Export an OpenPGP public key from a KMS key. Jar must sit next to this script.
# Usage: kms-export.sh --key KEY --user-name NAME --user-email EMAIL --out FILE
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 --key KEY --user-name NAME --user-email EMAIL --out FILE" >&2
  echo "Env: KMSPGP_KMS_KEY, KMSPGP_USER_NAME, KMSPGP_USER_EMAIL" >&2
  exit 1
}

KEY="${KMSPGP_KMS_KEY:-}"
USER_NAME="${KMSPGP_USER_NAME:-}"
USER_EMAIL="${KMSPGP_USER_EMAIL:-}"
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) [[ $# -ge 2 ]] || usage; KEY="$2"; shift 2 ;;
    --user-name) [[ $# -ge 2 ]] || usage; USER_NAME="$2"; shift 2 ;;
    --user-email) [[ $# -ge 2 ]] || usage; USER_EMAIL="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

require_val --key KMSPGP_KMS_KEY "$KEY"
require_val --user-name KMSPGP_USER_NAME "$USER_NAME"
require_val --user-email KMSPGP_USER_EMAIL "$USER_EMAIL"
if [[ -z "$OUT" ]]; then
  echo "error: --out FILE is required" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
echo "Exporting OpenPGP public key from KMS:" >&2
echo "  key:  $KEY" >&2
echo "  uid:  $USER_NAME <$USER_EMAIL>" >&2
echo "  file: $OUT" >&2
kmspgp export --user-name "$USER_NAME" --user-email "$USER_EMAIL" "$KEY" > "$OUT"
echo "Wrote $OUT" >&2

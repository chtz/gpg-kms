#!/usr/bin/env bash
# Export the kmspgp test key's public part. Looks up the KMS key by the alias
# created in create_test_key.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

OUT="${1:-kmspgp-pub.asc}"

init_aws
require_jar

key_id="$(lookup_test_key_id)"

kmspgp export \
  --user-name "Test" \
  --user-email "test@example.com" \
  "$key_id" > "$OUT"

echo "Exported public key:"
echo "  alias: $ALIAS_NAME"
echo "  key:   $key_id"
echo "  file:  $OUT"

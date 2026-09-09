#!/usr/bin/env bash
# Sign testartifact.txt with the KMS test key via kmspgp's GPG-compatible interface.
# Looks up the KMS key by the alias created in create_test_key.sh.
# Writes a detached armored signature; does not use ~/.gnupg.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

ARTIFACT="${1:-testartifact.txt}"
SIGNATURE="${ARTIFACT}.asc"

init_aws
require_jar

if [[ ! -f "$ARTIFACT" ]]; then
  echo "File to sign not found: $ARTIFACT" >&2
  exit 1
fi

key_id="$(lookup_test_key_id)"

# -bsau is gpg's detached, armored, local-user sign. kmspgp intercepts it and
# signs with KMS instead of a local secret key.
kmspgp -bsau "$key_id" < "$ARTIFACT" > "$SIGNATURE"

echo "Signed with KMS key via gpg-compatible kmspgp:"
echo "  alias:     $ALIAS_NAME"
echo "  key:       $key_id"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo
echo "Verify with:"
echo "  ./verify_with_test_key.sh $ARTIFACT"

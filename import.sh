#!/usr/bin/env bash
# Import an ASCII-armored public key into the public-only verification keyring.
# Usage: import.sh <pubkey.asc> [keyring-home]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <pubkey.asc> [keyring-home]" >&2
  exit 1
fi

ASC_FILE="$1"
KEYRING_HOME="${2:-$SCRIPT_DIR/keyring}"

if [[ ! -f "$ASC_FILE" ]]; then
  echo "error: public key file not found: $ASC_FILE" >&2
  exit 1
fi

if ! grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$ASC_FILE"; then
  echo "error: $ASC_FILE does not contain a PGP public key block" >&2
  exit 1
fi

if grep -q -- '-----BEGIN PGP PRIVATE KEY BLOCK-----' "$ASC_FILE"; then
  echo "error: $ASC_FILE contains a private key; the verification keyring is public-only" >&2
  exit 1
fi

mkdir -p "$KEYRING_HOME"
chmod 700 "$KEYRING_HOME"

FPRS=()
while IFS= read -r fpr; do
  FPRS+=("$fpr")
done < <(
  gpg --show-keys --with-colons "$ASC_FILE" \
    | awk -F: '/^pub:/{want=1; next} /^fpr:/ && want {print $10; want=0}'
)

if [[ ${#FPRS[@]} -eq 0 ]]; then
  echo "error: no public key found in $ASC_FILE" >&2
  exit 1
fi

gpg --homedir "$KEYRING_HOME" --batch --import "$ASC_FILE"

for fpr in "${FPRS[@]}"; do
  gpg --homedir "$KEYRING_HOME" --batch --import-ownertrust <<EOF
${fpr}:6:
EOF
done

if gpg --homedir "$KEYRING_HOME" --list-secret-keys --with-colons | grep -q '^sec:'; then
  echo "error: verification keyring unexpectedly contains secret keys" >&2
  exit 1
fi

echo "Imported ${#FPRS[@]} public key(s) from $ASC_FILE into $KEYRING_HOME"
for fpr in "${FPRS[@]}"; do
  echo "  $fpr"
done

#!/usr/bin/env bash
# Verify a detached signature that was made with a key not in the keyring
# (must fail), import that public key, then verify again (must succeed).
# Usage: import-and-verify.sh [signature] [artifact] [pubkey.asc] [keyring-home]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -gt 4 ]]; then
  echo "Usage: $0 [signature] [artifact] [pubkey.asc] [keyring-home]" >&2
  exit 1
fi

SIGNATURE="${1:-$SCRIPT_DIR/kmspgp/testartifact.txt.asc}"
ARTIFACT="${2:-$SCRIPT_DIR/kmspgp/testartifact.txt}"
PUBKEY="${3:-$SCRIPT_DIR/kmspgp/kmspgp-pub.asc}"
KEYRING_HOME="${4:-$SCRIPT_DIR/keyring}"

if [[ ! -f "$SIGNATURE" ]]; then
  echo "error: signature not found: $SIGNATURE" >&2
  exit 1
fi
if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ! -f "$PUBKEY" ]]; then
  echo "error: public key not found: $PUBKEY" >&2
  exit 1
fi

echo "==> Verifying signature before import (expect failure: public key not in keyring)"
if "$SCRIPT_DIR/verify.sh" "$SIGNATURE" "$ARTIFACT" "$KEYRING_HOME"; then
  echo "error: signature unexpectedly verified before import" >&2
  exit 1
fi
echo "OK: verification failed as expected (public key not in keyring)"

echo "==> Importing public key"
"$SCRIPT_DIR/import.sh" "$PUBKEY" "$KEYRING_HOME"

echo "==> Verifying signature after import (expect success)"
"$SCRIPT_DIR/verify.sh" "$SIGNATURE" "$ARTIFACT" "$KEYRING_HOME"

echo
echo "Done."
echo "  Verification failed before import, then succeeded after import."
echo "  signature:  $SIGNATURE"
echo "  artifact:   $ARTIFACT"
echo "  public key: $PUBKEY"
echo "  keyring:    $KEYRING_HOME"

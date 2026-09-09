#!/usr/bin/env bash
# Verify a detached signature against the public-only keyring.
# Usage: verify.sh <signature> <artifact> [keyring-home]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <signature> <artifact> [keyring-home]" >&2
  exit 1
fi

SIGNATURE="$1"
ARTIFACT="$2"
KEYRING_HOME="${3:-$SCRIPT_DIR/keyring}"

if [[ ! -f "$SIGNATURE" ]]; then
  echo "error: signature not found: $SIGNATURE" >&2
  exit 1
fi
if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ! -d "$KEYRING_HOME" ]]; then
  echo "error: keyring not found: $KEYRING_HOME" >&2
  exit 1
fi

gpg --homedir "$KEYRING_HOME" \
    --status-fd 1 \
    --verify "$SIGNATURE" "$ARTIFACT"

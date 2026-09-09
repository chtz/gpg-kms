#!/usr/bin/env bash
# Import kmspgp-pub.asc into an isolated GPG homedir under ./gpg_temp.
# Clears that directory first so a new test key can be imported cleanly.
# Does not touch ~/.gnupg.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_key_common.sh
source "$SCRIPT_DIR/test_key_common.sh"

PUB_KEY="${1:-kmspgp-pub.asc}"
GPG_HOME="${GPG_TEMP_HOME:-$PWD/$DEFAULT_GPG_HOME_NAME}"

require_isolated_gpg_home "$GPG_HOME"

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required but was not found on PATH." >&2
  exit 1
fi

if [[ ! -f "$PUB_KEY" ]]; then
  echo "Public key file not found: $PUB_KEY" >&2
  echo "Run ./export_test_key.sh first, or pass a path: $0 /path/to/key.asc" >&2
  exit 1
fi

if [[ -e "$GPG_HOME" ]]; then
  echo "Clearing isolated GPG homedir: $GPG_HOME"
  rm -rf "$GPG_HOME"
fi

mkdir -p "$GPG_HOME"
chmod 700 "$GPG_HOME"

gpg --homedir "$GPG_HOME" --batch --import "$PUB_KEY"

echo
echo "Imported into isolated GPG homedir:"
echo "  $GPG_HOME"
echo
gpg --homedir "$GPG_HOME" --list-keys

echo
echo "Use this homedir for later commands, for example:"
echo "  ./verify_with_test_key.sh"
echo "  gpg --homedir $GPG_HOME --list-keys"

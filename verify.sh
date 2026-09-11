#!/usr/bin/env bash
# Verify a detached OpenPGP signature against a public key file (no keyring, no AWS).
# Usage: verify.sh --pubkey FILE <artifact>
#        verify.sh --pubkey FILE <signature> <artifact>
#        verify.sh --check-pin FILE
set -euo pipefail

usage() {
  echo "Usage: $0 --pubkey FILE <artifact>" >&2
  echo "       $0 --pubkey FILE <signature> <artifact>" >&2
  echo "       $0 --check-pin FILE" >&2
  echo "Env: KMSPGP_PUBKEY" >&2
  echo "Default signature path: <artifact>.asc" >&2
  echo "The pin must contain exactly one primary OpenPGP key." >&2
  exit 1
}

require_gpg() {
  if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg is required but was not found on PATH." >&2
    exit 1
  fi
}

require_one_primary_key() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "error: public key not found: $file" >&2
    exit 1
  fi
  if ! grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$file"; then
    echo "error: $file does not contain a PGP public key block" >&2
    exit 1
  fi
  require_gpg
  local tmp listing pub_count
  tmp="$(mktemp -d)"
  chmod 700 "$tmp"
  listing="$(gpg --homedir "$tmp" --batch --yes --no-autostart --with-colons --show-keys "$file" 2>/dev/null)" || {
    rm -rf "$tmp"
    echo "error: gpg could not read $file" >&2
    exit 1
  }
  rm -rf "$tmp"
  pub_count="$(printf '%s\n' "$listing" | awk -F: '/^pub:/{c++} END{print c+0}')"
  if [[ "$pub_count" -ne 1 ]]; then
    echo "error: $file must contain exactly one primary OpenPGP key (found $pub_count)" >&2
    exit 1
  fi
  PIN_FINGERPRINT="$(printf '%s\n' "$listing" | awk -F: '/^fpr:/{print toupper($10); exit}')"
}

PUBKEY="${KMSPGP_PUBKEY:-}"
POSITIONAL=()
CHECK_PIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pubkey)
      [[ $# -ge 2 ]] || usage
      PUBKEY="$2"
      shift 2
      ;;
    --check-pin)
      [[ $# -ge 2 ]] || usage
      CHECK_PIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    --*)
      usage
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ -n "$CHECK_PIN" ]]; then
  if [[ ${#POSITIONAL[@]} -ne 0 || -n "$PUBKEY" ]]; then
    usage
  fi
  require_one_primary_key "$CHECK_PIN"
  echo "Pin $CHECK_PIN contains exactly one primary OpenPGP key."
  echo "fingerprint: $PIN_FINGERPRINT"
  exit 0
fi

if [[ -z "$PUBKEY" ]]; then
  echo "error: --pubkey FILE is required (or set KMSPGP_PUBKEY)" >&2
  exit 1
fi

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  ARTIFACT="${POSITIONAL[0]}"
  SIGNATURE="${ARTIFACT}.asc"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  SIGNATURE="${POSITIONAL[0]}"
  ARTIFACT="${POSITIONAL[1]}"
else
  usage
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ! -f "$SIGNATURE" ]]; then
  echo "error: signature not found: $SIGNATURE" >&2
  exit 1
fi

require_one_primary_key "$PUBKEY"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
chmod 700 "$TMP"

gpg --homedir "$TMP" --batch --yes --no-autostart --import "$PUBKEY" >/dev/null 2>&1

echo "Verifying:"
echo "  artifact:  $ARTIFACT"
echo "  signature: $SIGNATURE"
echo "  pubkey:    $PUBKEY"
echo

if command -v gpgv >/dev/null 2>&1; then
  gpg --homedir "$TMP" --batch --no-autostart --export -o "$TMP/trustedkeys.gpg" >/dev/null 2>&1
  gpgv --homedir "$TMP" --keyring "$TMP/trustedkeys.gpg" "$SIGNATURE" "$ARTIFACT"
else
  gpg --homedir "$TMP" --batch --no-autostart --status-fd 1 --verify "$SIGNATURE" "$ARTIFACT"
fi

#!/usr/bin/env bash
# Generate three signing keypairs, sign artifact.txt with each private key,
# and verify signatures against a public-only keyring that contains only
# the first two public keys. Signatures 1 and 2 must succeed; signature 3
# must fail because its public key is not in the keyring.
#
# Each run replaces keys/, keyring data, and test-out/ with new material.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gpg-common.sh
source "$SCRIPT_DIR/gpg-common.sh"

ARTIFACT="${1:-$SCRIPT_DIR/artifact.txt}"
KEYS_DIR="${KEYS_DIR:-$SCRIPT_DIR/keys}"
VERIFY_HOME="${VERIFY_HOME:-$SCRIPT_DIR/keyring}"
TEST_OUT="${TEST_OUT:-$SCRIPT_DIR/test-out}"

if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi

SIGNER1_HOME="$KEYS_DIR/signer1"
SIGNER2_HOME="$KEYS_DIR/signer2"
SIGNER3_HOME="$KEYS_DIR/signer3"
SIG1="$TEST_OUT/artifact.signer1.sig"
SIG2="$TEST_OUT/artifact.signer2.sig"
SIG3="$TEST_OUT/artifact.signer3.sig"
PUB1="$KEYS_DIR/signer1.pub.asc"
PUB2="$KEYS_DIR/signer2.pub.asc"
PUB3="$KEYS_DIR/signer3.pub.asc"

echo "==> Resetting key material and testrun output"
rm -rf "$KEYS_DIR" "$TEST_OUT"
mkdir -p "$SIGNER1_HOME" "$SIGNER2_HOME" "$SIGNER3_HOME" "$VERIFY_HOME" "$TEST_OUT"
chmod 700 "$SIGNER1_HOME" "$SIGNER2_HOME" "$SIGNER3_HOME" "$VERIFY_HOME"
# Recreate a clean public-only keyring without deleting keyring/.gitignore.
find "$VERIFY_HOME" -mindepth 1 ! -name '.gitignore' -exec rm -rf {} +

generate_signing_key() {
  local homedir="$1"
  local uid="$2"
  # Unprotected Ed25519 signing key (no passphrase; demo / local use only).
  gpg_unattended "$homedir" --quick-generate-key "$uid" ed25519 sign never
}

echo "==> Generating signing keypair 1"
generate_signing_key "$SIGNER1_HOME" "Signer One <signer1@gpg-kms.local>"
FPR1="$(secret_key_fingerprint "$SIGNER1_HOME")"

echo "==> Generating signing keypair 2"
generate_signing_key "$SIGNER2_HOME" "Signer Two <signer2@gpg-kms.local>"
FPR2="$(secret_key_fingerprint "$SIGNER2_HOME")"

echo "==> Generating signing keypair 3 (public key will NOT be in the keyring)"
generate_signing_key "$SIGNER3_HOME" "Signer Three <signer3@gpg-kms.local>"
FPR3="$(secret_key_fingerprint "$SIGNER3_HOME")"

echo "==> Exporting public keys"
gpg --homedir "$SIGNER1_HOME" --armor --export "$FPR1" > "$PUB1"
gpg --homedir "$SIGNER2_HOME" --armor --export "$FPR2" > "$PUB2"
gpg --homedir "$SIGNER3_HOME" --armor --export "$FPR3" > "$PUB3"

echo "==> Building public-only verification keyring (signer1 + signer2 only)"
gpg --homedir "$VERIFY_HOME" --batch --import "$PUB1" "$PUB2"
gpg --homedir "$VERIFY_HOME" --batch --import-ownertrust <<EOF
${FPR1}:6:
${FPR2}:6:
EOF

if gpg --homedir "$VERIFY_HOME" --list-secret-keys --with-colons | grep -q '^sec:'; then
  echo "error: verification keyring unexpectedly contains secret keys" >&2
  exit 1
fi

echo "==> Signing artifact with private key 1"
"$SCRIPT_DIR/sign.sh" "$SIGNER1_HOME" "$ARTIFACT" "$SIG1"

echo "==> Signing artifact with private key 2"
"$SCRIPT_DIR/sign.sh" "$SIGNER2_HOME" "$ARTIFACT" "$SIG2"

echo "==> Signing artifact with private key 3"
"$SCRIPT_DIR/sign.sh" "$SIGNER3_HOME" "$ARTIFACT" "$SIG3"

echo "==> Verifying signature 1 (signer1) against public-only keyring"
"$SCRIPT_DIR/verify.sh" "$SIG1" "$ARTIFACT" "$VERIFY_HOME"

echo "==> Verifying signature 2 (signer2) against public-only keyring"
"$SCRIPT_DIR/verify.sh" "$SIG2" "$ARTIFACT" "$VERIFY_HOME"

echo "==> Verifying signature 3 (signer3) against public-only keyring (expect failure)"
if "$SCRIPT_DIR/verify.sh" "$SIG3" "$ARTIFACT" "$VERIFY_HOME"; then
  echo "error: signature 3 (signer3) unexpectedly verified" >&2
  exit 1
fi
echo "OK: signature 3 (signer3) failed as expected (public key not in keyring)"

echo
echo "Done."
echo "  Signatures 1 and 2 verified against the public-only keyring."
echo "  Signature 3 failed verification (signer 3 public key was not imported)."
echo "  artifact:              $ARTIFACT"
echo "  signer 1 fingerprint:  $FPR1"
echo "  signer 2 fingerprint:  $FPR2"
echo "  signer 3 fingerprint:  $FPR3  (not in keyring)"
echo "  private key homes:     $KEYS_DIR/signer{1,2,3}  (gitignored)"
echo "  public key 1:          $PUB1"
echo "  public key 2:          $PUB2"
echo "  public key 3:          $PUB3  (exported, not imported)"
echo "  verification keyring:  $VERIFY_HOME  (commit this to distribute)"
echo "  signature 1:           $SIG1"
echo "  signature 2:           $SIG2"
echo "  signature 3:           $SIG3"
echo
echo "Public keys in the verification keyring:"
gpg --homedir "$VERIFY_HOME" --list-keys --fingerprint

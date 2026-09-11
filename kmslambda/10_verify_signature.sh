#!/usr/bin/env bash
# Verify the KMS ECDSA signature against artifact bytes and /public-key.
# Default file: the path stored at create. Pass a path to check a different file.
# This is raw ECDSA (DER), not OpenPGP — gpg --verify will not work.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

require_node

if [[ ! -f "$LAST_REQUEST_FILE" ]]; then
  echo "Missing $LAST_REQUEST_FILE. Run ./08_create_signing_request.sh and ./09_poll_signing_request.sh first." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but was not found on PATH." >&2
  exit 1
fi

eval "$(python3 - "$LAST_REQUEST_FILE" <<'PY'
import json, shlex, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
poll = doc.get("poll") or {}
if poll.get("status") != "SIGNED" or not poll.get("signature"):
    sys.exit("Poll result is not SIGNED. Run ./09_poll_signing_request.sh after Approve.")
artifact = doc.get("artifact") or ""
signed_digest = (poll.get("artifactDigest") or doc.get("digest") or "").lower()
sig = poll["signature"]
pubkey_url = poll.get("publicKeyUrl") or ""
if not pubkey_url:
    sys.exit("No publicKeyUrl in poll result.")
print("SIGNED_ARTIFACT=" + shlex.quote(artifact))
print("SIGNED_DIGEST=" + shlex.quote(signed_digest))
print("SIG_B64=" + shlex.quote(sig))
print("PUBKEY_URL=" + shlex.quote(pubkey_url))
PY
)"

if [[ -n "${1:-}" ]]; then
  ARTIFACT="$1"
else
  ARTIFACT="$SIGNED_ARTIFACT"
fi
if [[ ! -f "$ARTIFACT" ]]; then
  echo "Artifact not found: $ARTIFACT" >&2
  echo "Usage: $0 [path-to-artifact]" >&2
  exit 1
fi
ARTIFACT="$(cd "$(dirname "$ARTIFACT")" && pwd)/$(basename "$ARTIFACT")"
if [[ -f "$SIGNED_ARTIFACT" ]]; then
  SIGNED_ARTIFACT="$(cd "$(dirname "$SIGNED_ARTIFACT")" && pwd)/$(basename "$SIGNED_ARTIFACT")"
fi

CWD_CANDIDATE="$(pwd)/testartifact.txt"
if [[ -f "$CWD_CANDIDATE" ]]; then
  CWD_CANDIDATE="$(cd "$(dirname "$CWD_CANDIDATE")" && pwd)/$(basename "$CWD_CANDIDATE")"
  if [[ "$CWD_CANDIDATE" != "$ARTIFACT" ]]; then
    echo "Note: verifying $ARTIFACT" >&2
    echo "      $(pwd)/testartifact.txt is a different file. To check that one:" >&2
    echo "      $0 ./testartifact.txt" >&2
    echo >&2
  fi
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

curl -sS "$PUBKEY_URL" > "$WORKDIR/public-key.json"
python3 - "$WORKDIR/public-key.json" "$WORKDIR/pubkey.pem" "$WORKDIR/sig.der" "$SIG_B64" <<'PY'
import base64, json, sys
src, pem_path, sig_path, sig_b64 = sys.argv[1:5]
doc = json.load(open(src, encoding="utf-8"))
pem = doc.get("publicKeyPem")
if not pem:
    sys.exit("public-key response missing publicKeyPem")
open(pem_path, "w", encoding="utf-8").write(pem)
open(sig_path, "wb").write(base64.b64decode(sig_b64))
PY

echo "Verifying KMS ECDSA_SHA_256 over current artifact bytes:"
echo "  artifact: $ARTIFACT"
echo "  signed:   $SIGNED_DIGEST  ($SIGNED_ARTIFACT)"
echo "  pubkey:   $PUBKEY_URL"
echo

cat > "$WORKDIR/verify.js" <<'JS'
const fs = require("fs");
const crypto = require("crypto");
const [artifact, signedDigest, pemPath, sigPath] = process.argv.slice(2);
const data = fs.readFileSync(artifact);
const fileDigest = crypto.createHash("sha256").update(data).digest("hex");
const key = fs.readFileSync(pemPath, "utf8");
const sig = fs.readFileSync(sigPath);
const ok = crypto.verify("sha256", data, { key, dsaEncoding: "der" }, sig);
console.log("  file:     " + fileDigest);
if (fileDigest !== signedDigest) {
  console.error("Artifact bytes have changed since signing (SHA-256 mismatch).");
  process.exit(1);
}
if (!ok) {
  console.error("ECDSA verification failed for the current artifact.");
  process.exit(1);
}
JS

node "$WORKDIR/verify.js" "$ARTIFACT" "$SIGNED_DIGEST" "$WORKDIR/pubkey.pem" "$WORKDIR/sig.der"

echo
echo "Signature is valid for this artifact (ECDSA over SHA-256; not OpenPGP)."

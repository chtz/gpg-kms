#!/usr/bin/env bash
# Hash an artifact (SHA-256) and invoke the signing Lambda directly (create).
# Default artifact: testdata/artifact.txt
# Approval happens via SNS; this script only starts the request and prints pollUrl.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ARTIFACT="${1:-$DEFAULT_ARTIFACT}"
if [[ ! -f "$ARTIFACT" ]]; then
  echo "Artifact not found: $ARTIFACT" >&2
  echo "Usage: $0 [path-to-artifact]" >&2
  exit 1
fi
ARTIFACT="$(cd "$(dirname "$ARTIFACT")" && pwd)/$(basename "$ARTIFACT")"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to hash the artifact but was not found on PATH." >&2
  exit 1
fi

DIGEST="$(openssl dgst -sha256 "$ARTIFACT" | awk '{print $NF}')"
ARTIFACT_NAME="$(basename "$ARTIFACT")"

init_aws
FUNCTION_NAME="$(tf_output lambda_function_name)"

echo "Creating signing request with:"
echo "  profile:  ${PROFILE:-<default>}"
echo "  region:   $REGION"
echo "  function: $FUNCTION_NAME"
echo "  artifact: $ARTIFACT"
echo "  digest:   $DIGEST"
echo

PAYLOAD_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$PAYLOAD_FILE" "$RESPONSE_FILE"' EXIT

cat > "$PAYLOAD_FILE" <<EOF
{"action":"create","digest":"$DIGEST","artifact":"$ARTIFACT_NAME","version":"test","environment":"test"}
EOF

aws_cli lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --cli-binary-format raw-in-base64-out \
  --payload "file://${PAYLOAD_FILE}" \
  "$RESPONSE_FILE" >/dev/null

python3 - "$LAST_REQUEST_FILE" "$ARTIFACT" "$DIGEST" "$RESPONSE_FILE" <<'PY'
import json, sys
out_path, artifact, digest, resp_path = sys.argv[1:5]
with open(resp_path, encoding="utf-8") as f:
    response = json.load(f)
doc = {"artifact": artifact, "digest": digest, "response": response}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(json.dumps(response, indent=2))
PY

echo
echo "Wrote $LAST_REQUEST_FILE"
if python3 -c "import json; d=json.load(open('$LAST_REQUEST_FILE')); r=d['response']; raise SystemExit(0 if r.get('ok') else 1)"; then
  echo "SNS will email the approval link (not returned here)."
  echo
  echo "Next:"
  echo "  approve via the SNS link, then"
  echo "  ./09_poll_signing_request.sh"
else
  echo "Create failed. See the Lambda response above." >&2
  exit 1
fi

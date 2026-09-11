#!/usr/bin/env bash
# Poll GET {pollUrl} until SIGNED, FAILED, or REJECTED.
# Reads pollUrl from last-signing-request.json (written by 08).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

INTERVAL="${POLL_INTERVAL:-2}"
TIMEOUT="${POLL_TIMEOUT:-180}"

if [[ ! -f "$LAST_REQUEST_FILE" ]]; then
  echo "Missing $LAST_REQUEST_FILE. Run ./08_create_signing_request.sh first." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but was not found on PATH." >&2
  exit 1
fi

POLL_URL="$(python3 - "$LAST_REQUEST_FILE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
url = (doc.get("response") or {}).get("pollUrl")
if not url:
    sys.exit("No pollUrl in last-signing-request.json")
print(url)
PY
)"

echo "Polling signing request:"
echo "  url:      $POLL_URL"
echo "  interval: ${INTERVAL}s"
echo "  timeout:  ${TIMEOUT}s"
echo

deadline=$((SECONDS + TIMEOUT))
status=""
while (( SECONDS < deadline )); do
  body="$(mktemp)"
  http_code="$(curl -sS -o "$body" -w "%{http_code}" "$POLL_URL" || true)"
  python3 - "$LAST_REQUEST_FILE" "$body" "$http_code" <<'PY'
import json, sys
out_path, body_path, code = sys.argv[1:4]
doc = json.load(open(out_path, encoding="utf-8"))
raw = open(body_path, encoding="utf-8").read()
try:
    poll = json.loads(raw)
except json.JSONDecodeError:
    poll = {"ok": False, "error": raw or f"HTTP {code}"}
doc["poll"] = poll
doc["pollHttpCode"] = int(code)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
if isinstance(poll, dict):
    status = poll.get("status") or poll.get("error") or f"HTTP {code}"
    print(json.dumps(poll, indent=2))
    print(f"status: {status}", file=sys.stderr)
PY
  rm -f "$body"

  status="$(python3 -c "import json; print(json.load(open('$LAST_REQUEST_FILE')).get('poll',{}).get('status') or '')")"
  case "$status" in
    SIGNED)
      echo
      echo "Request signed. Signature is in $LAST_REQUEST_FILE (poll.signature)."
      echo
      echo "Next:"
      echo "  ./10_verify_signature.sh"
      exit 0
      ;;
    FAILED|REJECTED)
      echo
      echo "Request ended with status $status." >&2
      exit 1
      ;;
  esac
  sleep "$INTERVAL"
  echo
done

echo "Timed out after ${TIMEOUT}s waiting for SIGNED (last status: ${status:-unknown})." >&2
echo "Approve via the SNS link, then re-run ./09_poll_signing_request.sh" >&2
exit 1

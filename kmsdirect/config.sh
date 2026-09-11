#!/usr/bin/env bash
# Direct-KMS backend config. Prints sourceable export lines to stdout.
# Usage: ./config.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

if [[ $# -gt 0 ]]; then
  echo "Usage: $0" >&2
  echo "Redirect stdout to a file and source it, e.g. $0 > env && . ./env" >&2
  exit 1
fi

init_aws

if ! lookup_signing_key_id >/dev/null; then
  exit 1
fi

cat <<EOF
export AWS_REGION=$(printf '%q' "$REGION")
export KMSPGP_KMS_KEY=$(printf '%q' "$ALIAS_NAME")
EOF

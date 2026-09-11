#!/usr/bin/env bash
# Install npm dependencies from package-lock.json (npm ci).
# After git clone this is the first Node step; 04_build.sh also runs it if node_modules is missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

npm_ci

echo
echo "Installed node_modules from package-lock.json"
echo
echo "Next:"
echo "  ./04_build.sh"

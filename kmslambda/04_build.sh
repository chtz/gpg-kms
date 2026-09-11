#!/usr/bin/env bash
# Build the Lambda bundle (dist/index.js) that Terraform packages.
# Runs npm ci first when node_modules is missing (fresh clone).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ensure_node_modules

echo "Building Lambda bundle in $KMSLAMBDA_DIR"
echo

cd "$KMSLAMBDA_DIR"
npm run build

echo
echo "Built dist/index.js"
echo
echo "Next:"
echo "  ./05_terraform_plan.sh"

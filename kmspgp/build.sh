#!/usr/bin/env bash
# Build the runnable kmspgp jar into ../dist/kmspgp.jar (Java 25+, Maven 3.x).
# Wrappers already live in ../dist/; this only produces the jar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

if ! command -v java >/dev/null 2>&1; then
  echo "java is required but was not found on PATH. Install Java 25+." >&2
  exit 1
fi
if ! command -v mvn >/dev/null 2>&1; then
  echo "Apache Maven is required but was not found on PATH." >&2
  exit 1
fi

echo "Building kmspgp (Java 25+, Maven) in $SCRIPT_DIR"
echo

(cd "$SCRIPT_DIR" && mvn -q -DskipTests package)

mkdir -p "$DIST_DIR"
cp "$SCRIPT_DIR/target/kmspgp.jar" "$DIST_DIR/kmspgp.jar"

echo "Built:"
echo "  $DIST_DIR/kmspgp.jar"
echo
echo "Wrappers in $DIST_DIR call this jar (it must sit next to them)."

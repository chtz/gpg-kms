#!/usr/bin/env bash
# Helpers for dist wrappers. Source from a sibling script. Jar is always this directory.

DIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$DIST_DIR/kmspgp.jar"

require_java() {
  if ! command -v java >/dev/null 2>&1; then
    echo "java is required but was not found on PATH. Install Java 25+." >&2
    exit 1
  fi
}

require_jar() {
  require_java
  if [[ ! -f "$JAR" ]]; then
    echo "kmspgp.jar not found in $DIST_DIR" >&2
    echo "Run ../kmspgp/build.sh, or copy kmspgp.jar next to these scripts." >&2
    exit 1
  fi
}

kmspgp() {
  require_jar
  java -jar "$JAR" "$@"
}

require_val() {
  local flag="$1"
  local env_name="$2"
  local value="$3"
  if [[ -z "$value" ]]; then
    echo "error: $flag is required (or set $env_name)" >&2
    exit 1
  fi
}

#!/usr/bin/env bash
# Detached OpenPGP signature via kmslambda (human approval).
# Jar must sit next to this script. Does not read Terraform.
# Usage: lambda-sign.sh --function NAME <artifact> [output.asc]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: $0 --function NAME [--version VER] [--environment ENV] <artifact> [output.asc]" >&2
  echo "Env: KMSPGP_LAMBDA_FUNCTION_NAME, KMSPGP_VERSION, KMSPGP_ENVIRONMENT" >&2
  exit 1
}

FUNCTION="${KMSPGP_LAMBDA_FUNCTION_NAME:-}"
VERSION="${KMSPGP_VERSION:-}"
ENVIRONMENT="${KMSPGP_ENVIRONMENT:-}"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --function) [[ $# -ge 2 ]] || usage; FUNCTION="$2"; shift 2 ;;
    --version) [[ $# -ge 2 ]] || usage; VERSION="$2"; shift 2 ;;
    --environment) [[ $# -ge 2 ]] || usage; ENVIRONMENT="$2"; shift 2 ;;
    -h|--help) usage ;;
    --*) usage ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

require_val --function KMSPGP_LAMBDA_FUNCTION_NAME "$FUNCTION"
[[ ${#POSITIONAL[@]} -ge 1 && ${#POSITIONAL[@]} -le 2 ]] || usage

ARTIFACT="${POSITIONAL[0]}"
if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  OUTPUT="${POSITIONAL[1]}"
else
  OUTPUT="${ARTIFACT}.asc"
fi

mkdir -p "$(dirname "$OUTPUT")"
echo "Signing via kmslambda (approve the SNS link while this waits):"
echo "  artifact:  $ARTIFACT"
echo "  signature: $OUTPUT"
[[ -n "$VERSION" ]] && echo "  version:   $VERSION"
[[ -n "$ENVIRONMENT" ]] && echo "  env:       $ENVIRONMENT"
echo

lambda_args=(lambda-sign --function "$FUNCTION" --artifact "$ARTIFACT")
if [[ -n "$VERSION" ]]; then
  lambda_args+=(--version "$VERSION")
fi
if [[ -n "$ENVIRONMENT" ]]; then
  lambda_args+=(--environment "$ENVIRONMENT")
fi
kmspgp "${lambda_args[@]}" < "$ARTIFACT" > "$OUTPUT"
echo "Signed $ARTIFACT -> $OUTPUT"

#!/bin/sh
set -eu

tmp="$(mktemp)"
status=0

cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT INT TERM

if parsedmarc "$@" >"$tmp" 2>&1; then
  status=0
else
  status=$?
fi

cat "$tmp"

# Defensive fallback: force non-zero exit when known sink failures appear in logs.
if grep -Eiq "Elasticsearch (exception|Error)|OpenSearch (exception|Error)|Failed to save to (Elasticsearch|OpenSearch)" "$tmp"; then
  status=1
fi

exit "$status"

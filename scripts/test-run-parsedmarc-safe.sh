#!/bin/sh
set -eu

WRAPPER="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/run-parsedmarc-safe.sh"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

PATH="$tmpdir:$PATH"

run_case() {
  case_name="$1"
  fake_exit="$2"
  fake_log="$3"
  want_exit="$4"

  cat > "$tmpdir/parsedmarc" <<SCRIPT
#!/bin/sh
printf '%s\n' "$fake_log"
exit $fake_exit
SCRIPT
  chmod +x "$tmpdir/parsedmarc"

  got_log="$tmpdir/${case_name}.log"
  set +e
  "$WRAPPER" -c /tmp/parsedmarc.ini >"$got_log" 2>&1
  got_exit="$?"
  set -e

  if [ "$got_exit" -ne "$want_exit" ]; then
    echo "FAIL ${case_name}: expected exit ${want_exit}, got ${got_exit}" >&2
    echo "--- output ---" >&2
    cat "$got_log" >&2
    exit 1
  fi

  if ! grep -Fq "$fake_log" "$got_log"; then
    echo "FAIL ${case_name}: wrapper did not preserve parsedmarc output" >&2
    exit 1
  fi

  echo "PASS ${case_name}"
}

run_case "success" 0 "ok" 0
run_case "failure-no-sink" 42 "normal runtime error" 42
run_case "success-with-sink-error" 0 "Failed to save to Elasticsearch" 1
run_case "failure-with-sink-error" 17 "OpenSearch Error: boom" 1

echo "All wrapper safety tests passed."

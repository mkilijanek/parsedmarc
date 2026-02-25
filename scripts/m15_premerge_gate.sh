#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
RUNS="${RUNS:-1}"
DURATION="${DURATION:-10}"
CONCURRENCY="${CONCURRENCY:-24}"
MIN_MIXED_RPS="${MIN_MIXED_RPS:-700}"
MAX_MIXED_P95_MS="${MAX_MIXED_P95_MS:-350}"
MAX_ERROR_RATE="${MAX_ERROR_RATE:-0.01}"
OUT_DIR="${OUT_DIR:-/tmp/m15-gate}"
PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

echo "[M15 gate] pytest..."
"${PYTHON_BIN}" -m pytest -q

echo "[M15 gate] benchmark suite..."
"${PYTHON_BIN}" scripts/benchmark_suite_m14.py \
  --base-url "${BASE_URL}" \
  --duration "${DURATION}" \
  --concurrency "${CONCURRENCY}" \
  --runs "${RUNS}" \
  --output-dir "${OUT_DIR}"

echo "[M15 gate] evaluating thresholds..."
"${PYTHON_BIN}" - <<PY
import json, sys
from pathlib import Path

report = json.loads(Path("${OUT_DIR}/suite-summary.json").read_text(encoding="utf-8"))
mixed = report["scenarios"]["mixed"]
rps = float(mixed["throughput_rps_median"])
p95 = float(mixed["latency_ms_median"]["p95"])
err = float(mixed["error_rate_median"])

ok = True
if rps < float("${MIN_MIXED_RPS}"):
    print(f"[FAIL] throughput_rps_median {rps:.2f} < ${MIN_MIXED_RPS}")
    ok = False
if p95 > float("${MAX_MIXED_P95_MS}"):
    print(f"[FAIL] mixed p95 {p95:.2f} ms > ${MAX_MIXED_P95_MS} ms")
    ok = False
if err > float("${MAX_ERROR_RATE}"):
    print(f"[FAIL] mixed error rate {err:.6f} > ${MAX_ERROR_RATE}")
    ok = False

print(
    f"[M15 gate] mixed: rps={rps:.2f}, p95={p95:.2f}ms, error={err:.6f} "
    f"(thresholds: rps>=${MIN_MIXED_RPS}, p95<=${MAX_MIXED_P95_MS}, err<=${MAX_ERROR_RATE})"
)
sys.exit(0 if ok else 1)
PY

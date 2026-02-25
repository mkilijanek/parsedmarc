#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${OUT_FILE:-/tmp/m16-readiness.json}"
RUN_CHAOS="${RUN_CHAOS:-true}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

echo "[M16] pytest..."
"${PYTHON_BIN}" -m pytest -q

echo "[M16] m15 gate..."
RUNS="${RUNS:-1}" \
DURATION="${DURATION:-8}" \
CONCURRENCY="${CONCURRENCY:-16}" \
MIN_MIXED_RPS="${MIN_MIXED_RPS:-400}" \
MAX_MIXED_P95_MS="${MAX_MIXED_P95_MS:-500}" \
MAX_ERROR_RATE="${MAX_ERROR_RATE:-0.02}" \
BASE_URL="${BASE_URL}" \
bash scripts/m15_premerge_gate.sh

CHAOS_STATUS="skipped"
if [ "${RUN_CHAOS}" = "true" ]; then
  echo "[M16] m15 chaos check..."
  BASE_URL="${BASE_URL}" bash scripts/m15_chaos_check.sh
  CHAOS_STATUS="passed"
fi

"${PYTHON_BIN}" - <<PY
import json
from datetime import datetime, timezone
report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": "go",
    "checks": {
        "pytest": "passed",
        "m15_gate": "passed",
        "m15_chaos_check": "${CHAOS_STATUS}",
    },
    "notes": [
        "M16 release readiness check completed.",
        "Use docs/m16-finalization.md for final go/no-go checklist."
    ],
}
with open("${OUT_FILE}", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
    f.write("\\n")
print(json.dumps(report, indent=2))
PY

echo "[M16] readiness report: ${OUT_FILE}"

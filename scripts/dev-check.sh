#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ ! -x ".venv/bin/python" ]]; then
  bash scripts/dev-bootstrap.sh
fi

bash scripts/dev-python.sh python -m compileall -q app tests
bash scripts/dev-test.sh "$@"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VENV_DIR="${VENV_DIR:-.venv}"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "Missing ${VENV_DIR}. Run: bash scripts/dev-bootstrap.sh" >&2
  exit 1
fi

source "${VENV_DIR}/bin/activate"
export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"

if [[ $# -eq 0 ]]; then
  exec python
fi

exec "$@"

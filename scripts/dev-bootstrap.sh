#!/usr/bin/env bash
# dev-bootstrap.sh — one-shot dev environment setup
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Missing ${PYTHON_BIN} in PATH." >&2
  exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements-dev.txt

# IBM Plex fonts are bundled in app/static/fonts/ (SIL OFL 1.1).
# No external download required — fonts are baked into the Docker image.
if [[ ! -f "app/static/fonts/IBMPlexSans-Regular.woff2" ]]; then
  echo "WARNING: app/static/fonts/ is missing WOFF2 files." >&2
  echo "Run: git lfs pull  (or check that git clone completed fully)" >&2
fi

echo ""
echo "Dev environment ready."
echo "Python: $(python --version 2>&1)"
echo "Pip:    $(pip --version 2>&1)"
echo ""
echo "Quick commands:"
echo "  make test          — run full test suite"
echo "  make test-fast     — skip integration tests"
echo "  make lint          — ruff check + format"
echo "  docker compose up  — start all services (postgres, redis, app, worker)"
echo "  scripts/dev-env.sh — print env var reference"

#!/usr/bin/env bash
set -euo pipefail

# This script must be sourced to persist environment changes in current shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "Use: source scripts/dev-env.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ ! -f ".venv/bin/activate" ]]; then
  echo "Missing .venv. Create it with: python3 -m venv .venv"
  return 1
fi
source ".venv/bin/activate"

export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [[ ! -s "${NVM_DIR}/nvm.sh" ]]; then
  echo "Missing nvm at ${NVM_DIR}. Install nvm first."
  return 1
fi
source "${NVM_DIR}/nvm.sh"

if [[ -f ".nvmrc" ]]; then
  nvm use >/dev/null
else
  nvm use --lts >/dev/null
fi

echo "Python: $(python --version 2>&1)"
echo "Node:   $(node -v)"
echo "npm:    $(npm -v)"
if command -v jq >/dev/null 2>&1; then
  echo "jq:     $(jq --version)"
else
  echo "jq:     missing (install with: npm i -g jq-cli-wrapper)"
fi

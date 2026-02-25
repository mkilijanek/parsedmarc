#!/usr/bin/env bash
set -euo pipefail

# This script must be sourced to keep exported variables in current shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "Use: source scripts/load-secrets.sh [path-to-env-file]"
  exit 1
fi

SECRETS_FILE="${1:-$HOME/.secrets/ioc-service.env}"

if [[ ! -f "${SECRETS_FILE}" ]]; then
  echo "Secrets file not found: ${SECRETS_FILE}"
  echo "Create it (outside repo) with lines like:"
  echo "  ABUSECH_AUTH_KEY=..."
  echo "  MWDB_AUTH_KEY=..."
  echo "  MALWAREBAZAAR_AUTH_KEY=..."
  return 1
fi

set -a
# shellcheck source=/dev/null
source "${SECRETS_FILE}"
set +a

echo "Loaded secrets from ${SECRETS_FILE}"

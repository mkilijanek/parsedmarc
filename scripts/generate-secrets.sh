#!/usr/bin/env sh
set -eu

# Generates strong secrets for .env usage.
# No external deps required (uses openssl if present, otherwise python).

gen_hex() {
  nbytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$nbytes"
  else
    python3 - <<PY
import secrets
print(secrets.token_hex($nbytes))
PY
  fi
}

echo "POSTGRES_PASSWORD=$(gen_hex 32)"
echo "REDIS_PASSWORD=$(gen_hex 32)"
echo "SECRET_KEY=$(gen_hex 32)"

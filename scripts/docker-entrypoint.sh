#!/usr/bin/env sh
set -eu

# Auto-fill required runtime settings for containerized runs.
# Values can still be overridden explicitly via environment variables.

if [ -z "${SECRET_KEY:-}" ]; then
  SECRET_KEY="$(python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  export SECRET_KEY
fi

if [ -z "${DATABASE_URL:-}" ]; then
  export DATABASE_URL="postgresql+psycopg2://threatfeed:threatfeed@postgres:5432/threatfeed"
fi

if [ -z "${REDIS_URL:-}" ]; then
  export REDIS_URL="redis://:redispass@redis:6379/0"
fi

exec "$@"

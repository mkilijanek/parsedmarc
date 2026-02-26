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

# Ensure ORM tables exist unless explicitly disabled.
if [ "${AUTO_DB_INIT:-true}" = "true" ]; then
  python - <<'PY'
from app.db import Base, engine
from app import models  # noqa: F401 - register metadata
from sqlalchemy import text

lock_id = 937451
with engine.begin() as conn:
    if engine.dialect.name == "postgresql":
        # Prevent parallel schema creation across app/worker containers.
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": lock_id})
    try:
        Base.metadata.create_all(bind=conn)
        print("AUTO_DB_INIT: schema ensured")
    finally:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
PY
fi

# Optional one-shot benchmark mode.
# Usage:
#   docker compose run --rm app --benchmark
#   docker compose run --rm -e BENCHMARK_BASE_URL=http://app:8080 app --benchmark --duration 20 --concurrency 64
if [ "${1:-}" = "--benchmark" ]; then
  shift
  BENCHMARK_BASE_URL="${BENCHMARK_BASE_URL:-http://app:8080}"
  BENCHMARK_DURATION="${BENCHMARK_DURATION:-30}"
  BENCHMARK_CONCURRENCY="${BENCHMARK_CONCURRENCY:-64}"
  BENCHMARK_TIMEOUT="${BENCHMARK_TIMEOUT:-5}"
  BENCHMARK_OUTPUT_JSON="${BENCHMARK_OUTPUT_JSON:-/tmp/m12-benchmark.json}"

  echo "BENCHMARK: starting (base_url=${BENCHMARK_BASE_URL}, duration=${BENCHMARK_DURATION}s, concurrency=${BENCHMARK_CONCURRENCY})"
  python /app/scripts/benchmark_m12.py \
    --base-url "${BENCHMARK_BASE_URL}" \
    --duration "${BENCHMARK_DURATION}" \
    --concurrency "${BENCHMARK_CONCURRENCY}" \
    --timeout "${BENCHMARK_TIMEOUT}" \
    --output-json "${BENCHMARK_OUTPUT_JSON}" \
    "$@"
  echo "BENCHMARK: completed (report=${BENCHMARK_OUTPUT_JSON})"
  exit 0
fi

exec "$@"

#!/usr/bin/env sh
set -eu

# Fail fast for cryptographic identity instead of auto-generating a new key
# per container start. Runtime-generated keys break session compatibility
# and secret decryption across restarts and replicas.
if [ -z "${SECRET_KEY:-}" ]; then
  echo "SECURITY ERROR: SECRET_KEY environment variable must be set before container startup." >&2
  exit 1
fi

if [ -z "${DATABASE_URL:-}" ]; then
  export DATABASE_URL="postgresql+psycopg2://threatfeed:threatfeed@postgres:5432/threatfeed"
fi

if [ -z "${REDIS_URL:-}" ]; then
  export REDIS_URL="redis://:redispass@redis:6379/0"
fi

AUTO_MIGRATE_ON_START="${AUTO_MIGRATE_ON_START:-true}"
cmdline="$*"
should_run_migrations="false"

if [ "${AUTO_MIGRATE_ON_START}" = "true" ]; then
  case "${cmdline}" in
    *gunicorn*|*app.worker*)
      should_run_migrations="true"
      ;;
  esac
fi

if [ "${1:-}" != "--benchmark" ] && [ "${should_run_migrations}" = "true" ]; then
  echo "STARTUP: applying database migrations (alembic upgrade head)"
  sh /app/scripts/db-migrate.sh
  echo "STARTUP: database migrations completed"
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

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

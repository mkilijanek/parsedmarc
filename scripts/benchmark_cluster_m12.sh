#!/usr/bin/env bash
set -euo pipefail

REPLICAS="${1:-4}"
DURATION="${2:-20}"
CONCURRENCY="${3:-64}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

COMPOSE=(sudo docker compose -f docker-compose.yml)
PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

PROJECT_NAME="$(basename "${PROJECT_DIR}")"
NETWORK_NAME="${PROJECT_NAME}_default"
IMAGE_NAME="${PROJECT_NAME}-app"
APP_PREFIX="ioc-bench-app"

cleanup_apps() {
  local ids
  ids="$(sudo docker ps -aq --filter "name=^/${APP_PREFIX}-")"
  if [[ -n "${ids}" ]]; then
    sudo docker rm -f ${ids} >/dev/null
  fi
}

start_apps() {
  local count="$1"
  cleanup_apps
  for i in $(seq 1 "${count}"); do
    sudo docker run -d \
      --name "${APP_PREFIX}-${i}" \
      --network "${NETWORK_NAME}" \
      -e LOG_LEVEL=ERROR \
      -e SECRET_KEY=cluster-benchmark-secret-key-minimum-32-chars \
      -e CACHE_TTL=300 \
      -e APP_PORT=8080 \
      -e RATE_LIMITS_ENABLED=false \
      -e REQUESTS_PER_SECOND_MAX=1000000 \
      -e DATABASE_URL=postgresql+psycopg2://threatfeed:threatfeed@postgres:5432/threatfeed \
      -e REDIS_URL=redis://:redispass@redis:6379/0 \
      "${IMAGE_NAME}" >/dev/null
  done
}

echo "[1/6] Starting cluster dependencies and building app image..."
"${COMPOSE[@]}" up -d --build postgres redis
sudo docker compose -f docker-compose.yml build app >/dev/null
start_apps 1

APP_IDS=($(sudo docker ps -q --filter "name=^/${APP_PREFIX}-"))
if [[ "${#APP_IDS[@]}" -lt 1 ]]; then
  echo "No app container found for baseline benchmark." >&2
  exit 1
fi

BASELINE_IP="$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${APP_IDS[0]}")"
BASELINE_URL="http://${BASELINE_IP}:8080"

echo "[2/6] Running baseline benchmark (1 replica) on ${BASELINE_URL}..."
"${PYTHON_BIN}" scripts/benchmark_m12.py \
  --base-url "${BASELINE_URL}" \
  --duration "${DURATION}" \
  --concurrency "${CONCURRENCY}" \
  --output-json /tmp/m12-baseline.json >/tmp/m12-baseline-print.json

echo "[3/6] Scaling app to ${REPLICAS} replicas..."
start_apps "${REPLICAS}"
APP_IDS=($(sudo docker ps -q --filter "name=^/${APP_PREFIX}-"))
if [[ "${#APP_IDS[@]}" -lt "${REPLICAS}" ]]; then
  echo "Expected ${REPLICAS} app containers, got ${#APP_IDS[@]}." >&2
  exit 1
fi

URLS=()
for cid in "${APP_IDS[@]}"; do
  ip="$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cid}")"
  URLS+=("http://${ip}:8080")
done
BASE_URLS="$(IFS=,; echo "${URLS[*]}")"

echo "[4/6] Running cluster benchmark against ${#URLS[@]} app replicas..."
"${PYTHON_BIN}" scripts/benchmark_m12.py \
  --base-url "${BASE_URLS}" \
  --duration "${DURATION}" \
  --concurrency "${CONCURRENCY}" \
  --output-json /tmp/m12-cluster.json >/tmp/m12-cluster-print.json

echo "[5/6] Calculating speedup..."
"${PYTHON_BIN}" - <<'PY'
import json

with open("/tmp/m12-baseline.json", "r", encoding="utf-8") as f:
    base = json.load(f)
with open("/tmp/m12-cluster.json", "r", encoding="utf-8") as f:
    cluster = json.load(f)

base_rps = float(base.get("throughput_rps", 0.0))
cluster_rps = float(cluster.get("throughput_rps", 0.0))
speedup = (cluster_rps / base_rps) if base_rps > 0 else 0.0

summary = {
    "baseline_rps": round(base_rps, 2),
    "cluster_rps": round(cluster_rps, 2),
    "speedup_x": round(speedup, 2),
    "baseline_error_rate": base.get("error_rate", 0.0),
    "cluster_error_rate": cluster.get("error_rate", 0.0),
    "baseline_latency_ms": base.get("latency_ms", {}),
    "cluster_latency_ms": cluster.get("latency_ms", {}),
}
print(json.dumps(summary, indent=2))
with open("/tmp/m12-cluster-summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
PY

echo "[6/6] Done. Reports:"
echo "  - /tmp/m12-baseline.json"
echo "  - /tmp/m12-cluster.json"
echo "  - /tmp/m12-cluster-summary.json"

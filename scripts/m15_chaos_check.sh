#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
COMPOSE_CMD="${COMPOSE_CMD:-sudo docker compose}"
RUN_DB_RESTART="${RUN_DB_RESTART:-true}"
RUN_REDIS_PAUSE="${RUN_REDIS_PAUSE:-true}"
RUN_PACKET_LOSS="${RUN_PACKET_LOSS:-false}"
APP_SERVICE="${APP_SERVICE:-app}"

echo "[M15 chaos] baseline checks..."
curl -fsS "${BASE_URL}/health" >/dev/null
curl -fsS "${BASE_URL}/indicators?limit=10" >/dev/null
curl -fsS "${BASE_URL}/indicators/json?limit=10" >/dev/null

echo "[M15 chaos] stop redis..."
${COMPOSE_CMD} stop redis >/dev/null
sleep 2

# Endpoints with fallback should stay available.
curl -fsS "${BASE_URL}/indicators?limit=10" >/dev/null
curl -fsS "${BASE_URL}/indicators/json?limit=10" >/dev/null
curl -fsS "${BASE_URL}/correlations?min_sources=2&limit=20" >/dev/null
curl -fsS "${BASE_URL}/health" >/dev/null

echo "[M15 chaos] start redis..."
${COMPOSE_CMD} start redis >/dev/null
sleep 2

curl -fsS "${BASE_URL}/health" >/dev/null
curl -fsS "${BASE_URL}/metrics" >/dev/null || true

if [ "${RUN_DB_RESTART}" = "true" ]; then
  echo "[M15 chaos] restart postgres..."
  ${COMPOSE_CMD} stop postgres >/dev/null || true
  sleep 2
  curl -fsS "${BASE_URL}/health" >/dev/null || true
  ${COMPOSE_CMD} start postgres >/dev/null || true
  sleep 3
  curl -fsS "${BASE_URL}/health" >/dev/null
  curl -fsS "${BASE_URL}/indicators?limit=10" >/dev/null
fi

if [ "${RUN_REDIS_PAUSE}" = "true" ]; then
  echo "[M15 chaos] pause/unpause redis (slow cache simulation)..."
  ${COMPOSE_CMD} pause redis >/dev/null || true
  sleep 3
  curl -fsS "${BASE_URL}/indicators?limit=10" >/dev/null || true
  ${COMPOSE_CMD} unpause redis >/dev/null || true
  sleep 1
  curl -fsS "${BASE_URL}/health" >/dev/null
fi

if [ "${RUN_PACKET_LOSS}" = "true" ]; then
  echo "[M15 chaos] packet loss simulation (best effort)..."
  set +e
  ${COMPOSE_CMD} exec -T "${APP_SERVICE}" sh -lc "command -v tc >/dev/null && tc qdisc add dev eth0 root netem loss 15% delay 200ms"
  sleep 2
  curl -fsS "${BASE_URL}/health" >/dev/null || true
  ${COMPOSE_CMD} exec -T "${APP_SERVICE}" sh -lc "command -v tc >/dev/null && tc qdisc del dev eth0 root netem"
  set -e
fi

echo "[M15 chaos] OK"

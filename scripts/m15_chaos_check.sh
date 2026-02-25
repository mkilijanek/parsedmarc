#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
COMPOSE_CMD="${COMPOSE_CMD:-sudo docker compose}"

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
curl -fsS "${BASE_URL}/metrics" >/dev/null

echo "[M15 chaos] OK"

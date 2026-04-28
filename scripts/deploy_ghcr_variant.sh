#!/usr/bin/env bash
set -euo pipefail

variant="${1:-ioc-service}"
image_tag="${2:-latest}"

export APP_IMAGE_REPOSITORY="${APP_IMAGE_REPOSITORY:-ghcr.io/mkilijanek/ioc-service}"
export TLS_IMAGE_REPOSITORY="${TLS_IMAGE_REPOSITORY:-ghcr.io/mkilijanek/ioc-service-tls}"
export IMAGE_TAG="${image_tag}"
export TLS_IMAGE_TAG="${TLS_IMAGE_TAG:-${image_tag}}"

compose=(docker compose -f docker-compose-release.yml)

case "${variant}" in
  ioc-service)
    export EDGE_HTTPS_ENABLED=false
    export HSTS_ENABLED=false
    export SESSION_COOKIE_SECURE_ENABLED=false
    export NGINX_TLS_ENABLED=false
    export NGINX_HSTS_ENABLED=false
    ;;
  ioc-service-tls)
    export EDGE_HTTPS_ENABLED=true
    export HSTS_ENABLED="${HSTS_ENABLED:-true}"
    export SESSION_COOKIE_SECURE_ENABLED="${SESSION_COOKIE_SECURE_ENABLED:-true}"
    export NGINX_TLS_ENABLED=true
    export NGINX_HSTS_ENABLED="${NGINX_HSTS_ENABLED:-${HSTS_ENABLED}}"
    ;;
  *)
    echo "Unsupported variant: ${variant}" >&2
    exit 1
    ;;
esac

echo "[deploy] variant=${variant} image_tag=${image_tag}"
docker pull "${APP_IMAGE_REPOSITORY}:${IMAGE_TAG}"
if [ "${variant}" = "ioc-service-tls" ]; then
  docker pull "${TLS_IMAGE_REPOSITORY}:${TLS_IMAGE_TAG}"
fi

"${compose[@]}" up -d postgres redis
"${compose[@]}" run --rm migrate

if [ "${variant}" = "ioc-service-tls" ]; then
  "${compose[@]}" --profile edge up -d app worker nginx
else
  "${compose[@]}" rm -sf nginx >/dev/null 2>&1 || true
  "${compose[@]}" up -d app worker
fi

"${compose[@]}" ps

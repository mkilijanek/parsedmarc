#!/bin/sh

PARSEDMARC_VERSION=${PARSEDMARC_VERSION:-9.0.11}
IMAGE_TAG=${IMAGE_TAG:-$PARSEDMARC_VERSION}
IMAGE_NAME=${IMAGE_NAME:-ghcr.io/mkilijanek/parsedmarc}

docker build \
  --build-arg PARSEDMARC_VERSION=${PARSEDMARC_VERSION} \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ${IMAGE_NAME}:${IMAGE_TAG} .

if [ -n "$GHCR_TOKEN" ]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "${GITHUB_USER}" --password-stdin
  docker push ${IMAGE_NAME}:${IMAGE_TAG}
fi

FROM python:3.15-alpine3.23@sha256:d64bc17e0dff27c5c4a31f616450d032aa73d6325855127ce3a305bf1384c8d5

ARG PARSEDMARC_VERSION=11.0.3
ARG VCS_REF=""
ARG BUILD_DATE=""
ARG SOURCE_DATE_EPOCH=""

ENV PARSEDMARC_VERSION=${PARSEDMARC_VERSION}

LABEL org.opencontainers.image.source="https://github.com/mkilijanek/parsedmarc" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${PARSEDMARC_VERSION}" \
      org.opencontainers.image.vendor="mkilijanek" \
      org.opencontainers.image.title="parsedmarc (containerized)"

RUN if [ -z "${SOURCE_DATE_EPOCH}" ]; then unset SOURCE_DATE_EPOCH; fi \
 && apk upgrade --no-cache \
 && apk add --no-cache curl \
 && python -m pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "parsedmarc[all]==${PARSEDMARC_VERSION}" "urllib3>=2.8.0" \
 && adduser -D -h /home/parsedmarc -u 1000 parsedmarc \
 && mkdir -p /home/parsedmarc/ini /var/log/parsedmarc \
 && chown -R 1000:1000 /home/parsedmarc /var/log/parsedmarc

USER parsedmarc
WORKDIR /home/parsedmarc

ENTRYPOINT ["parsedmarc"]
CMD ["-h"]

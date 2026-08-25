FROM python:3-alpine3.23@sha256:6b8f06d04d5305c1d1288435388df9165ab41e681fae6439d6349d8053cc3f83

ARG PARSEDMARC_VERSION=10.4.3
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
 && apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main zlib=1.3.2-r0 openssl musl=1.2.5-r23 \
 && apk add --no-cache curl sqlite-libs \
 && python -m pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "parsedmarc==${PARSEDMARC_VERSION}" "urllib3>=2.6.3" \
 && adduser -D -h /home/parsedmarc -u 1000 parsedmarc \
 && mkdir -p /home/parsedmarc/ini /var/log/parsedmarc \
 && chown -R 1000:1000 /home/parsedmarc /var/log/parsedmarc

USER parsedmarc
WORKDIR /home/parsedmarc

ENTRYPOINT ["parsedmarc"]
CMD ["-h"]

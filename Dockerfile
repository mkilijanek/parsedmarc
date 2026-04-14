FROM python:3-alpine3.23@sha256:01f125438100bb6b5770c0b1349e5200b23ca0ae20a976b5bd8628457af607ae

ARG PARSEDMARC_VERSION=9.5.4
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

RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main zlib=1.3.2-r0 \
 && python -m pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "parsedmarc==${PARSEDMARC_VERSION}" "urllib3>=2.6.3" \
 && adduser -D -h /home/parsedmarc -u 1000 parsedmarc \
 && mkdir -p /home/parsedmarc/ini /var/log/parsedmarc \
 && chown -R 1000:1000 /home/parsedmarc /var/log/parsedmarc

USER parsedmarc
WORKDIR /home/parsedmarc

ENTRYPOINT ["parsedmarc"]
CMD ["-h"]

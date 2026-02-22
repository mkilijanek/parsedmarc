FROM python:3-alpine3.23

ARG PARSEDMARC_VERSION=9.0.11
ARG VCS_REF=""
ARG BUILD_DATE=""

ENV PARSEDMARC_VERSION=${PARSEDMARC_VERSION}

LABEL org.opencontainers.image.source="https://github.com/mkilijanek/parsedmarc" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${PARSEDMARC_VERSION}"

RUN python -m pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "parsedmarc==${PARSEDMARC_VERSION}" \
 && adduser -D -h /home/parsedmarc -u 1000 parsedmarc \
 && mkdir -p /home/parsedmarc/ini /var/log/parsedmarc \
 && chown -R 1000:1000 /home/parsedmarc /var/log/parsedmarc

USER parsedmarc
WORKDIR /home/parsedmarc

ENTRYPOINT ["parsedmarc"]
CMD ["-h"]

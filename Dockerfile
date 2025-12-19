FROM python:3-alpine3.22

ARG PARSEDMARC_VERSION=8.18.6
ENV PARSEDMARC_VERSION=${PARSEDMARC_VERSION}

COPY requirements.txt /tmp/requirements.txt
RUN sed -i "s/^parsedmarc==.*/parsedmarc==${PARSEDMARC_VERSION}/" /tmp/requirements.txt && \
    pip install --no-cache-dir --upgrade -r /tmp/requirements.txt

RUN mkdir -p /home/parsedmarc
RUN adduser -D -h "/home/parsedmarc/" -u 1000 parsedmarc
RUN mkdir -p /home/parsedmarc/ini && chown -R parsedmarc: /home/parsedmarc/ini
USER parsedmarc

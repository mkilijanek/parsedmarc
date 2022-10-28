FROM python:3.12.0a1-alpine

RUN apk update && apk upgrade --available \
    && apk add build-base libxml2-dev libxslt-dev \
    && rm -rf /var/cache/apk/* \
    && pip install --no-cache --upgrade pip \
    && pip install --no-cache -U parsedmarc

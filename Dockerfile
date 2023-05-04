FROM python:3-alpine3.17

RUN apk update && apk upgrade --available \
    && apk add build-base libxml2-dev libxslt-dev libffi libffi-dev \
    && apk add --update alpine-sdk \
    && rm -rf /var/cache/apk/*
RUN pip install --no-cache --upgrade pip \
    && pip install --no-cache -U wheel \
    && pip install --no-cache -U setuptools \
    && pip install --no-cache -U parsedmarc==8.3.2

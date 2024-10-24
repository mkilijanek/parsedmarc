FROM python:alpine

ENV PARSEDMARC_VERSION=8.15.1

RUN apk update && apk upgrade --available \
    && apk add build-base libxml2-dev libxslt-dev libffi libffi-dev \
    && apk add --update alpine-sdk \
    && rm -rf /var/cache/apk/*
RUN pip install --no-cache --upgrade pip \
    && pip install --no-cache -U wheel \
    && pip install --no-cache -U setuptools \
    && pip install kafka-python-ng \
    && pip install --no-cache -U parsedmarc==${PARSEDMARC_VERSION}
RUN adduser -D parsedmarc
USER parsedmarc

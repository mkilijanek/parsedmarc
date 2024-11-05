FROM python:alpine

ENV PARSEDMARC_VERSION=8.16.0

RUN pip install --no-cache --upgrade parsedmarc==${PARSEDMARC_VERSION}
RUN adduser -D -m parsedmarc
USER parsedmarc

FROM python:alpine

ENV PARSEDMARC_VERSION=8.16.0

RUN pip install --no-cache --upgrade parsedmarc==${PARSEDMARC_VERSION}
RUN adduser -D -h "/home/parsedmarc/" -u 1000 parsedmarc
RUN mkdir -p /home/parsedmarc/ini && chown -R parsedmarc: /home/parsedmarc/ini 
USER parsedmarc


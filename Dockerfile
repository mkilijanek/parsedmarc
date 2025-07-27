FROM python:3.14.0rc1-alpine3.22

ENV PARSEDMARC_VERSION=8.18.5

RUN pip install --no-cache --upgrade parsedmarc==${PARSEDMARC_VERSION}
RUN mkdir -p /home/parsedmarc
RUN adduser -D -h "/home/parsedmarc/" -u 1000 parsedmarc
RUN mkdir -p /home/parsedmarc/ini && chown -R parsedmarc: /home/parsedmarc/ini 
USER parsedmarc


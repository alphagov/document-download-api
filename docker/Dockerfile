FROM python:3.9-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libcurl4-openssl-dev \
    libssl-dev \
    libmagic-dev \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

RUN groupadd -r notify && useradd -r -g notify notify

WORKDIR /home/vcap/app

COPY requirements.txt ./

RUN echo "Installing python dependencies" \
    && pip install -r requirements.txt

COPY app app
COPY application.py gunicorn_config.py ./

RUN chown -R notify:notify /home/vcap/app

USER notify

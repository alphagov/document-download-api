FROM python:3.13-slim-bookworm AS base

COPY --from=ghcr.io/astral-sh/uv:0.5.30 /uv /uvx /bin/

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_CACHE_DIR='/tmp/uv-cache/' \
    VIRTUAL_ENV="/opt/venv"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libcurl4-openssl-dev \
    libssl-dev \
    libmagic-dev \
    curl \
    media-types \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

WORKDIR /home/vcap/app

##### Python Build Image #####################################################
FROM base AS python_build

RUN echo "Install OS dependencies for python app requirements" &&  \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

COPY requirements.txt ./

RUN echo "Installing python dependencies" && \
    python3 -m venv /opt/venv && \
    uv pip sync --python /opt/venv/bin/python requirements.txt

COPY . .
RUN make generate-version-file  # This file gets copied across

##### Production Image #######################################################
FROM base AS production

RUN groupadd -r notify && useradd -r -g notify notify && chown -R notify:notify /home/vcap
USER notify

RUN mkdir /home/vcap/logs

COPY --from=python_build --chown=root:root /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY --chown=notify:notify app app
COPY --chown=notify:notify application.py entrypoint.sh gunicorn_config.py ./
COPY --from=python_build --chown=notify:notify /home/vcap/app/app/version.py app/version.py

RUN chown -R notify:notify /home/vcap/app

RUN python -m compileall . && \
    chown -R notify:notify /home/vcap/app && \
    chmod +x /home/vcap/app/entrypoint.sh

ENTRYPOINT [ "/home/vcap/app/entrypoint.sh" ]

##### Test Image ##############################################################
FROM production as test

USER root
RUN echo "Install OS dependencies for test build" \
    && apt-get update && \
    apt-get install -y --no-install-recommends \
      sudo \
      curl \
      git \
      make \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*
RUN usermod -aG sudo notify
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER notify

ENV HOME=/home/vcap

# Make sure the app/ directory is there so that "make bootstrap" can create app/version.py
RUN mkdir -p app

# Copying to overwrite is faster than RUN chown notify:notify ...
COPY --from=python_build --chown=notify:notify /opt/venv /opt/venv

# Install dev/test requirements
COPY --chown=notify:notify Makefile requirements_for_test.txt ./
RUN make bootstrap

# Copy from the real world, one dir up (project root) into the environment's current working directory
# Docker will rebuild from here down every time.
COPY --chown=notify:notify . .

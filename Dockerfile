# syntax = docker/dockerfile:1.16
########################################

FROM registry.k8s.io/pause:3.10 AS pause

########################################

FROM python:3.11.9-slim AS base

RUN --mount=type=cache,id=apt-cache-python,target=/var/cache/apt,sharing=locked \
    LC_ALL=C apt-get update -y && \
    LC_ALL=C apt-get install -y --no-install-recommends locales ca-certificates mime-support make libpq5 vim gettext procps && \
    sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen && LC_ALL=C locale-gen && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* && \
    adduser --disabled-password --home /home/app --uid 1100 --gecos "Payment" app

########################################

FROM base AS release
LABEL org.opencontainers.image.source="https://github.com/nvnv/betmaster" \
      org.opencontainers.image.description="Payment aggregator"

COPY --from=pause /pause /pause

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VIRTUALENVS_CREATE=false
RUN --mount=type=cache,id=apt-cache-python,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends build-essential python3-dev libpq-dev git && \
    rm -rf /var/lib/apt/lists/* /tmp/*
RUN --mount=type=cache,id=pip,target=/root/.cache pip install "poetry==1.4.2"

COPY --chown=app:app rozert-pay/poetry.lock rozert-pay/pyproject.toml /www/rozert-pay/
WORKDIR /www/rozert-pay

RUN poetry config virtualenvs.create false

RUN poetry install --no-interaction --no-ansi --no-root

ENV PYTHONPATH=/www/rozert-pay

USER app
COPY --chown=app:app rozert-pay /www/rozert-pay

ARG SHA
ENV GIT_SHA=${SHA}

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

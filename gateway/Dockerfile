FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra gateway

COPY gateway gateway

RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /app/gateway/config /app/gateway/runtime /run/secrets \
    && chown -R appuser:appuser /app /run/secrets \
    && chmod 0700 /app/gateway/runtime /run/secrets

USER appuser

EXPOSE 8082

HEALTHCHECK CMD curl --fail http://localhost:8082/healthcheck

CMD ["/app/.venv/bin/uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8082"]

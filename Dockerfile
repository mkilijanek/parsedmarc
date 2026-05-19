# syntax=docker/dockerfile:1.6
FROM python:3.11-slim AS builder
WORKDIR /build
# SECURITY: Install only necessary build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
# SECURITY: Create non-root user early in build process
RUN useradd -m -u 1000 appuser

WORKDIR /app
# SECURITY: Install only necessary runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl libpq5 && rm -rf /var/lib/apt/lists/*

# SECURITY: Copy files with proper ownership from the start
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local
COPY --chown=appuser:appuser app/ ./app/
COPY --chown=appuser:appuser docs/ ./docs/
COPY --chown=appuser:appuser scripts/ ./scripts/
COPY --chown=appuser:appuser alembic/ ./alembic/
COPY --chown=appuser:appuser alembic.ini ./alembic.ini
COPY --chown=appuser:appuser scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# SECURITY: Switch to non-root user before any operations
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${APP_PORT:-8080} --workers ${WORKERS:-3} --threads ${GUNICORN_THREADS:-8} --timeout ${GUNICORN_TIMEOUT:-120} --worker-class ${GUNICORN_WORKER_CLASS:-gthread} 'app.main:create_app()'"]

# Base digest-pinned (D9): python:3.11-slim
FROM python@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

# Create non-root user first
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# D9: dependencies BEFORE source — layer caching means source changes don't
# reinstall the world. The lockfile is the install source of truth.
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir -r requirements.lock

# Install the package without re-resolving deps (lockfile already installed them)
COPY pyproject.toml README.md ./
COPY nabla ./nabla
RUN pip install --no-cache-dir --no-deps .

# Fix ownership
RUN chown -R appuser:appgroup /app

# Data directory (named volumes inherit this ownership)
RUN mkdir -p /data && chown appuser:appgroup /data

USER appuser

# Default command — conditional: web server, scheduler mode, or idle for CLI use
# Set NABLA_WEB_ENABLED=1 to run the web server, NABLA_SCHEDULE_ENABLED=1 for scheduler
CMD ["sh", "-c", "if [ \"$NABLA_WEB_ENABLED\" = \"1\" ]; then nabla-web; elif [ \"$NABLA_SCHEDULE_ENABLED\" = \"1\" ]; then nabla schedule --interval \"${NABLA_SCHEDULE_INTERVAL:-5}\" --log-type \"${NABLA_SCHEDULE_LOG_TYPES:-all}\" --log-count \"${NABLA_SCHEDULE_LOG_COUNT:-50}\"; else sleep infinity; fi"]

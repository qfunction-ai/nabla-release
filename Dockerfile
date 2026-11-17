FROM python:3.11-slim

WORKDIR /app

# Create non-root user first
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy source
COPY . .

# Install (non-editable — source is baked into image)
RUN pip install --no-cache-dir .

# Fix ownership
RUN chown -R appuser:appgroup /app

# Data directory
RUN mkdir -p /data && chown appuser:appgroup /data

# Entrypoint: ensure volume ownership on restart
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

USER appuser

# Default command — conditional: web server, scheduler mode, or idle for CLI use
# Set NABLA_WEB_ENABLED=1 to run the web server, NABLA_SCHEDULE_ENABLED=1 for scheduler
# All env var expansions are quoted to prevent shell injection
CMD ["sh", "-c", "if [ \"$NABLA_WEB_ENABLED\" = \"1\" ]; then nabla-web; elif [ \"$NABLA_SCHEDULE_ENABLED\" = \"1\" ]; then nabla schedule --interval \"${NABLA_SCHEDULE_INTERVAL:-5}\" --log-type \"${NABLA_SCHEDULE_LOG_TYPES:-all}\" --log-count \"${NABLA_SCHEDULE_LOG_COUNT:-50}\"; else sleep infinity; fi"]

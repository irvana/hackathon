# =============================================================================
# Stage 1 – dependency builder
# Compiles/installs all Python packages into an isolated prefix so the final
# image only copies the pre-built wheels, keeping the layer cache efficient.
# =============================================================================
FROM python:3.11-slim AS builder

# Prevents .pyc files and enables unbuffered stdout for clean container logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build toolchain (needed for some wheels, e.g. uvloop inside uvicorn[standard])
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into /install prefix
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# =============================================================================
# Stage 2 – runtime image
# =============================================================================
FROM python:3.11-slim AS runtime

# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
LABEL maintainer="sre-team" \
      project="self-healing-shadow" \
      component="sre-agent-ecs"

# ---------------------------------------------------------------------------
# Runtime environment – all values are overridden at task/container launch
# ---------------------------------------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # ── Datadog ──────────────────────────────────────────────────────────────
    DD_API_KEY="" \
    DD_APP_KEY="" \
    DD_SITE="datadoghq.com" \
    DD_SERVICE="sre-agent-ecs" \
    DD_ENV="production" \
    DD_VERSION="1.0.0" \
    DD_TRACE_ENABLED="true" \
    DD_LOGS_INJECTION="true" \
    # ── AWS ──────────────────────────────────────────────────────────────────
    AWS_DEFAULT_REGION="us-east-1" \
    # ── App ──────────────────────────────────────────────────────────────────
    APP_HOST="0.0.0.0" \
    APP_PORT="8000" \
    APP_WORKERS="1"

# ---------------------------------------------------------------------------
# System packages:
#   - curl / ca-certificates : health-checks and HTTPS
#   - Node.js + npm          : REQUIRED — Datadog MCP server is launched via
#                              `npx @datadog/datadog-mcp-server` at runtime.
#                              Without Node.js the MCP subprocess will fail.
# ---------------------------------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        # Node.js 20 LTS (via NodeSource one-liner keeps the image reproducible)
        gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends \
        nodejs \
    && npm install -g npm@latest \
    # Warm the npx cache for the Datadog MCP server so first-run latency is low
    && npx --yes @datadog/datadog-mcp-server --version 2>/dev/null || true \
    # Cleanup
    && apt-get purge -y --auto-remove gnupg \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.npm/_npx/*cache*

# ---------------------------------------------------------------------------
# Copy pre-built Python packages from builder stage
# ---------------------------------------------------------------------------
COPY --from=builder /install /usr/local

# ---------------------------------------------------------------------------
# Application source
# ---------------------------------------------------------------------------
WORKDIR /app
COPY . .

# ---------------------------------------------------------------------------
# Non-root user for least-privilege operation (ECS task best practice)
# ---------------------------------------------------------------------------
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup --no-create-home appuser \
    && chown -R appuser:appgroup /app

USER appuser

# ---------------------------------------------------------------------------
# Port & health check
# ---------------------------------------------------------------------------
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ---------------------------------------------------------------------------
# Entrypoint
# ddtrace-run wraps uvicorn so every request and Bedrock call is auto-traced.
# To skip ddtrace (e.g. local dev), override ENTRYPOINT in docker-compose.
# ---------------------------------------------------------------------------
ENTRYPOINT ["ddtrace-run"]
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info", \
     "--access-log"]

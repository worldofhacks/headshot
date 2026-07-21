# AgentForge deployment/health surface — production-style image.
# spec(M1a:AC-1)
#
# Slim base, non-root runtime user, the package installed as a wheel (not a bind mount),
# an explicit healthcheck against the liveness probe. Local dev / synthetic data only —
# this image ships NO secrets and reaches NO live target; credentials are injected at run
# time via the secret manager (see agentforge.config, O1).

FROM python:3.12-slim AS base

# Predictable, quiet, unbuffered Python; no stale .pyc written into the image layers.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install curl for the container healthcheck, then drop apt lists to keep the image lean.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged runtime user; the process must never run as root.
RUN groupadd --system app && useradd --system --gid app --home-dir /app app

# Install the package. Copy the build inputs first so the layer caches on source changes.
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install .

USER app

EXPOSE 8000

# Liveness probe: /health returns 200 as long as the process can serve — it never touches
# the DB, so this reflects process health only (readiness is a separate /ready probe).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "agentforge.app:app", "--host", "0.0.0.0", "--port", "8000"]

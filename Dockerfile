# syntax=docker/dockerfile:1.7
# One reviewed artifact serves the public Web process and the private Runner/Scheduler.
# Node and build tooling remain in throwaway stages; the runtime receives only the built
# SPA, Python wheels, and the complete Alembic apply path.

FROM node:22.17.1-bookworm-slim AS console-build

ENV NODE_ENV=development \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

WORKDIR /build/console

# Clerk's Vite publishable key is a public, environment-specific identifier. Declaring it
# only in this build stage lets Railway provide it without placing any server secret in a
# layer or the final runtime environment.
ARG VITE_CLERK_PUBLISHABLE_KEY
ENV VITE_CLERK_PUBLISHABLE_KEY=${VITE_CLERK_PUBLISHABLE_KEY}

# Lockfile-first install keeps the reviewed dependency graph deterministic. Lifecycle
# scripts are unnecessary for this Vite build and remain disabled at the supply-chain edge.
COPY console/package.json console/package-lock.json ./
RUN npm ci --ignore-scripts

COPY console/ ./
RUN test -n "$VITE_CLERK_PUBLISHABLE_KEY" \
    && npm run build \
    && ! find dist -type f -name '*.map' -print -quit | grep -q .


FROM python:3.12.11-slim-bookworm AS wheel-build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .


FROM python:3.12.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --no-create-home app

COPY --from=wheel-build /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels agentforge==0.1.0 \
    && rm -rf /wheels

# Alembic runs in a Railway pre-deploy container. These files must be available in the
# final image, not merely in the Git checkout used by CI.
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations
COPY evals /app/evals

# Only compiled, production console assets cross the Node/runtime boundary.
COPY --from=console-build --chown=app:app /build/console/dist /app/console

RUN chown -R app:app /app
USER app

EXPOSE 8000

# Docker checks process liveness only. Railway promotion uses /ready, which additionally
# gates DB connectivity, exact migration head, and networkless Clerk configuration.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/health', timeout=2).read()"]

CMD ["python", "-m", "agentforge.web"]

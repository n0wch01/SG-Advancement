# Control plane image: API + bundled rules. Build context is the repo root.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra server --no-install-project
COPY src ./src
COPY rules ./rules
RUN uv sync --frozen --no-dev --extra server

ENV SENTINEL_DB_URL=sqlite:////data/sentinel.db SENTINEL_RULES_DIR=/app/rules \
    SENTINEL_SIGNING_KEY=/data/policy_signing_key.pem
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["sentinel-server", "--host", "0.0.0.0", "--port", "8000"]

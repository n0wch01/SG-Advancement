# Control plane image: API + bundled rules. Build context is the repo root.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra server --no-install-project
COPY src ./src
COPY rules ./rules
COPY integrations/openclaw-plugin ./integrations/openclaw-plugin
RUN uv sync --frozen --no-dev --extra server
# M12 one-line install: the sensor wheel and its dependencies pinned by hash, served at /install/.
RUN uv build --wheel --out-dir /opt/sga-install \
 && uv export --frozen --no-dev --extra openclaw --no-emit-project --format requirements-txt \
      -o /opt/sga-install/requirements.txt

ENV SGA_DB_URL=sqlite:////data/sga.db SGA_RULES_DIR=/app/rules \
    SGA_SIGNING_KEY=/data/policy_signing_key.pem SGA_INSTALL_DIR=/opt/sga-install \
    SGA_PLUGIN_DIR=/app/integrations/openclaw-plugin
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["sga-server", "--host", "0.0.0.0", "--port", "8000"]

# Team OpenClaw gateway host (M5b): the official OpenClaw image plus the SG-Advance sensor and
# gateway plugin, the way a company would install them on its shared gateway host.
#
# Images are pinned by digest. The OpenClaw version matches the npm release the control plane
# verified (openclaw@2026.11.3). Note: this image is built from source under /app, so it is not
# byte-identical to the npm package; the npm-based integrity check is off here and the image digest
# (with its build attestation) is the trust anchor instead.

# Python 3.12 for the sensor (the OpenClaw image ships Debian's 3.11).
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS sensor
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv venv /opt/sga/venv --python /usr/local/bin/python3.12 \
 && VIRTUAL_ENV=/opt/sga/venv uv pip install --no-cache ".[openclaw]"

FROM ghcr.io/openclaw/openclaw@sha256:adc5f5e9654afa3056666cb8f42415a72b91631fc301b382d5771456fee95477
USER root
# Same Debian base (bookworm): the interpreter and its stdlib copy over cleanly.
COPY --from=sensor /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=sensor /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=sensor /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/libpython3.12.so.1.0
COPY --from=sensor /opt/sga/venv /opt/sga/venv
RUN ldconfig && /opt/sga/venv/bin/sga-sensor --help >/dev/null
COPY integrations/openclaw-plugin /opt/sga/plugin
COPY deploy/team-gateway/team-config.json5 deploy/team-gateway/start.sh /opt/sga/
RUN chmod 0755 /opt/sga/start.sh && chown -R node:node /opt/sga/plugin \
 # Fresh named volumes copy these owners/modes; otherwise Docker makes them root-owned.
 && mkdir -p /home/node/.openclaw /home/node/.sg-advance \
 && chown node:node /home/node/.openclaw /home/node/.sg-advance \
 && chmod 700 /home/node/.sg-advance
USER node
ENTRYPOINT ["tini", "-s", "--", "/opt/sga/start.sh"]

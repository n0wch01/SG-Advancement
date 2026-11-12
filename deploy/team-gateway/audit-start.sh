#!/bin/sh
# SG-Advance audit proxy (M5b): between team-proxy and the gateway, records who approved or
# stopped what. Same image as the gateway (it has the sensor), its own sensor identity and home.
set -eu
SGA=/opt/sga/venv/bin/sga-sensor
SGA_HOME="$HOME/.sg-advance"
mkdir -p "$SGA_HOME"
chmod 700 "$SGA_HOME"

if [ ! -f "$SGA_HOME/credentials.json" ]; then
  : "${SGA_ENROLL_TOKEN:?not enrolled: set SGA_AUDIT_ENROLL_TOKEN in .env}"
  echo "[sga] enrolling the audit proxy with ${SGA_SERVER}"
  $SGA --home "$SGA_HOME" enroll --server "$SGA_SERVER" --device-id "${SGA_DEVICE_ID:-team-audit}"
fi

exec $SGA --home "$SGA_HOME" run --no-local-api \
  --openclaw-audit-proxy 0.0.0.0:18790 \
  --openclaw-audit-upstream "${SGA_AUDIT_UPSTREAM:-ws://172.28.0.20:18789}" \
  --audit-trusted-peer "${SGA_AUDIT_TRUSTED_PEER:-172.28.0.10}" \
  --user team-audit

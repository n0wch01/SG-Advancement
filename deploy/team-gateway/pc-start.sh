#!/bin/sh
# Demo employee PC (M5d shadow AI): carol installed OpenClaw on her own and runs it with her own
# settings, outside the company setup. The company endpoint sensor runs here too, but with no
# OpenClaw adapters: all it does about OpenClaw is the discovery scan (sga-sensor run --no-local-api).
set -eu
OC="node /app/openclaw.mjs"
SGA=/opt/sga/venv/bin/sga-sensor
STATE="$HOME/.openclaw"
SGA_HOME="$HOME/.sg-advance"
mkdir -p "$STATE" "$SGA_HOME"
chmod 700 "$STATE" "$SGA_HOME"

# A personal setup: no SG-Advance plugin, gateway opened to the LAN "to use it from the phone".
if [ ! -f "$STATE/openclaw.json" ]; then
  TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  umask 077
  cat >"$STATE/openclaw.json" <<JSON
{"gateway": {"mode": "local", "bind": "${PC_GATEWAY_BIND:-lan}", "port": 18789, "auth": {"mode": "token", "token": "$TOKEN"}}}
JSON
fi

if [ ! -f "$SGA_HOME/credentials.json" ]; then
  : "${SGA_ENROLL_TOKEN:?not enrolled: pass SGA_PC_ENROLL_TOKEN once}"
  echo "[sga] enrolling ${SGA_DEVICE_ID:-carol-pc} with ${SGA_SERVER}"
  $SGA --home "$SGA_HOME" enroll --server "$SGA_SERVER" --device-id "${SGA_DEVICE_ID:-carol-pc}"
fi

# The company sensor: discovery only (no gateway token, no plugin socket). Short interval for the demo.
(
  while true; do
    $SGA --home "$SGA_HOME" run --no-local-api --user "${SGA_DEFAULT_USER:-carol@corp.test}" \
      --discovery-interval "${SGA_DISCOVERY_INTERVAL:-30}" >>"$SGA_HOME/sensor.log" 2>&1 || true
    sleep 5
  done
) &

cd /app
exec $OC gateway

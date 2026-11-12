#!/bin/sh
# Team gateway host start: configure once, run the SG-Advance sensor next to the gateway, then
# hand PID 1's child slot to the official OpenClaw entrypoint.
set -eu
OC="node /app/openclaw.mjs"
SGA=/opt/sga/venv/bin/sga-sensor
STATE="$HOME/.openclaw"
SGA_HOME="$HOME/.sg-advance"
: "${OPENCLAW_GATEWAY_PASSWORD:?set OPENCLAW_GATEWAY_PASSWORD (same-host services use it)}"
mkdir -p "$STATE" "$SGA_HOME"
chmod 700 "$SGA_HOME"

# The company baseline is re-applied on every start, so the file stays the source of truth
# (a key changed in the UI is reset here; settings the file doesn't name are left alone).
echo "[sga] applying team gateway settings"
$OC config patch --file /opt/sga/team-config.json5
if [ ! -f "$STATE/.sga-configured" ]; then
  $OC plugins install --link /opt/sga/plugin --force --accept-capabilities
  touch "$STATE/.sga-configured"
fi

if [ ! -f "$SGA_HOME/credentials.json" ]; then
  if [ -n "${SGA_ENROLL_TOKEN:-}" ]; then
    echo "[sga] enrolling this gateway host with ${SGA_SERVER}"
    $SGA --home "$SGA_HOME" enroll --server "$SGA_SERVER" --device-id "${SGA_DEVICE_ID:-team-gateway}"
  else
    echo "[sga] not enrolled and no SGA_ENROLL_TOKEN: the sensor will not start"
  fi
fi

if [ -f "$SGA_HOME/credentials.json" ]; then
  # Keep the sensor up like a service manager would; its log stays in the sensor home.
  (
    while true; do
      $SGA --home "$SGA_HOME" run --openclaw ws://127.0.0.1:18789 --no-openclaw-integrity \
        --user "${SGA_DEFAULT_USER:-team-gateway}" >>"$SGA_HOME/sensor.log" 2>&1 || true
      sleep 5
    done
  ) &
fi

cd /app
exec node /app/docker-entrypoint.mjs node openclaw.mjs gateway

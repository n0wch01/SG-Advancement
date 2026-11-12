#!/bin/sh
# SG-Advance egress proxy (M5d): the agent network (team-net, internal) has no route out except
# through here. Same image as the gateway (it has the sensor), its own sensor identity and home.
set -eu
SGA=/opt/sga/venv/bin/sga-sensor
SGA_HOME="$HOME/.sg-advance"
mkdir -p "$SGA_HOME"
chmod 700 "$SGA_HOME"

if [ ! -f "$SGA_HOME/credentials.json" ]; then
  : "${SGA_ENROLL_TOKEN:?not enrolled: set SGA_EGRESS_ENROLL_TOKEN in .env}"
  echo "[sga] enrolling the egress proxy with ${SGA_SERVER}"
  $SGA --home "$SGA_HOME" enroll --server "$SGA_SERVER" --device-id "${SGA_DEVICE_ID:-team-egress}"
fi

# monitor (default): record and alert only. SGA_EGRESS_MODE=enforce refuses what the policy blocks.
MODE_FLAG=""
[ "${SGA_EGRESS_MODE:-monitor}" = "enforce" ] && MODE_FLAG="--egress-enforce"
exec $SGA --home "$SGA_HOME" run --no-local-api --egress-proxy 0.0.0.0:3128 $MODE_FLAG --user team-gateway

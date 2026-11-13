#!/bin/sh
# Central MCP gateway (2026-11-13, zero trust): the only path from employees' agents to company MCP
# servers. Reached only through the LAN gateway (device mTLS + per-request revocation check); it holds
# the servers' credentials (agents hold none) and judges every tools/call with the signed policy.
# Same image as the team gateway (it has the sensor), its own sensor identity and home.
set -eu
SGA=/opt/sga/venv/bin/sga-sensor
SGA_HOME="$HOME/.sg-advance"
mkdir -p "$SGA_HOME"
chmod 700 "$SGA_HOME"

if [ ! -f "$SGA_HOME/credentials.json" ]; then
  : "${SGA_ENROLL_TOKEN:?not enrolled: set SGA_MCP_ENROLL_TOKEN in .env}"
  echo "[sga] enrolling the central MCP gateway with ${SGA_SERVER}"
  $SGA --home "$SGA_HOME" enroll --server "$SGA_SERVER" --device-id "${SGA_DEVICE_ID:-mcp-gateway}"
fi
: "${CRM_TOKEN:?set SGA_CRM_TOKEN in .env (the corp-crm server's token, held only here)}"
: "${SGA_PROXY_SECRET:?set SGA_PROXY_SECRET in .env (shared with the LAN gateway)}"

exec $SGA --home "$SGA_HOME" run --no-local-api --no-discovery --no-claude-code --user mcp-gateway \
  --mcp-gateway 0.0.0.0:18790 \
  --mcp-server crm=http://corp-crm:18791/mcp --mcp-credential crm=CRM_TOKEN \
  --mcp-proxy-secret-env SGA_PROXY_SECRET --mcp-device-header x-sga-device --mcp-user-header x-sga-user

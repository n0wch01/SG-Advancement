#!/usr/bin/env bash
# Deploy the local demo stack in the order that has worked (docs/control-plane.md):
#   1. back up the control-plane DB   2. build the console   3. rebuild the control plane
#   4. restart the Mac sensor          5. rebuild the team gateway and its neighbours
#   6. recreate the LAN gateway when its nginx template changed   7. check every active device
#      picked up the new policy.
# Any failed step stops the run (set -e): a deploy without a backup does not go ahead.
# The admin token is read from .env and never printed.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/deploy.sh [--label NAME] [--no-dashboard] [--no-team] [--recreate-lan] [--dry-run]
  --label NAME     backup name suffix (default: pre-<commit>-<time>)
  --no-dashboard   skip the console build (dashboard/dist is served as is)
  --no-team        skip the team gateway, audit, egress, carol-pc, MCP gateway and corp-crm
  --recreate-lan   recreate the LAN gateway even if its template did not change
  --dry-run        print the steps, run nothing (no .env needed)
EOF
}

LABEL="" DASHBOARD=1 TEAM=1 RECREATE_LAN=0 DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --label) LABEL="${2:?--label needs a name}"; shift 2 ;;
    --no-dashboard) DASHBOARD=0; shift ;;
    --no-team) TEAM=0; shift ;;
    --recreate-lan) RECREATE_LAN=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
TEAM_SERVICES=(team-gateway team-audit team-egress carol-pc mcp-gateway corp-crm)
VERIFY_TIMEOUT="${SGA_DEPLOY_VERIFY_TIMEOUT:-150}"  # sensors sync every 60 s
ACTIVE_MINUTES="${SGA_DEPLOY_ACTIVE_MINUTES:-15}"   # devices seen within this window must be current

step() { printf '\n== %s\n' "$*"; }
run() {
  if [[ $DRY -eq 1 ]]; then printf '  $ %s\n' "$*"; else "$@"; fi
}

commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
LABEL="${LABEL:-pre-${commit}-$(date +%Y%m%d%H%M)}"
[[ "$LABEL" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "label must be [A-Za-z0-9._-]: $LABEL" >&2; exit 2; }

step "preflight (commit $commit)"
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  echo "  warning: uncommitted changes are deployed too"
fi
if [[ $DRY -eq 0 ]]; then
  [[ -f .env ]] || { echo ".env is missing (SGA_ADMIN_TOKEN)" >&2; exit 1; }
  set -a; . ./.env; set +a
  : "${SGA_ADMIN_TOKEN:?SGA_ADMIN_TOKEN is not set in .env}"
fi
API="http://127.0.0.1:${SGA_PORT:-8000}"

step "1. back up the control-plane DB → /data/sga.db.$LABEL"
backup_py="import sqlite3; s=sqlite3.connect('/data/sga.db'); d=sqlite3.connect('/data/sga.db.$LABEL'); s.backup(d); d.close(); print('  backup ok')"
if [[ $DRY -eq 1 ]] || [[ -n "$(docker compose ps -q --status running control-plane 2>/dev/null)" ]]; then
  run docker compose exec -T control-plane python3 -c "$backup_py"
else
  echo "  control plane is not running: nothing to back up (first deploy)"
fi

if [[ $DASHBOARD -eq 1 ]]; then
  step "2. build the console (dashboard/dist, mounted read-only into the control plane)"
  if [[ ! -d dashboard/node_modules ]]; then run npm --prefix dashboard ci; fi
  run npm --prefix dashboard run build
fi

step "3. rebuild the control plane"
run docker compose up -d --build control-plane
if [[ $DRY -eq 0 ]]; then
  for _ in $(seq 1 60); do curl -sf "$API/healthz" >/dev/null && break; sleep 1; done
  curl -sf "$API/healthz" >/dev/null || { echo "control plane did not come up on $API" >&2; exit 1; }
  echo "  healthy"
fi

step "4. restart the Mac sensor (LaunchAgent)"
if [[ "$(uname)" == Darwin ]] && launchctl print "gui/$(id -u)/com.sg-advance.sensor" >/dev/null 2>&1; then
  run launchctl kickstart -k "gui/$(id -u)/com.sg-advance.sensor"
elif [[ $DRY -eq 1 ]]; then
  run launchctl kickstart -k "gui/\$(id -u)/com.sg-advance.sensor"
else
  echo "  no sensor service on this machine: skipped"
fi

if [[ $TEAM -eq 1 ]]; then
  step "5. rebuild the team gateway and restart its neighbours"
  run docker compose --profile team build team-gateway
  run docker compose --profile team --profile shadow --profile mcp up -d --no-build "${TEAM_SERVICES[@]}"
fi

step "6. LAN gateway (nginx renders its template only at start)"
lan_id="$(docker compose --profile lan ps -q --status running lan-gateway 2>/dev/null || true)"
if [[ $DRY -eq 1 ]]; then
  run docker compose --profile lan up -d --force-recreate --no-deps lan-gateway
  run docker compose --profile lan exec -T lan-gateway nginx -t
elif [[ -z "$lan_id" ]]; then
  echo "  not running: skipped"
else
  started="$(docker inspect -f '{{.State.StartedAt}}' "$lan_id")"
  template=deploy/lan-gateway/default.conf.template
  changed="$(python3 - "$started" "$template" <<'PY'
import os, sys
from datetime import datetime
started = datetime.fromisoformat(sys.argv[1][:26].rstrip("Z") + "+00:00").timestamp()
print(1 if os.path.getmtime(sys.argv[2]) > started else 0)
PY
)"
  if [[ $RECREATE_LAN -eq 1 || "$changed" == 1 ]]; then
    run docker compose --profile lan up -d --force-recreate --no-deps lan-gateway
    sleep 2
    run docker compose --profile lan exec -T lan-gateway nginx -t
  else
    echo "  template unchanged since the gateway started: kept"
  fi
fi

step "7. every device seen in the last ${ACTIVE_MINUTES} min has the new policy (revoked ones skipped)"
if [[ $DRY -eq 1 ]]; then
  printf '  $ GET %s/v1/admin/devices (until policy_current, up to %ss)\n' "$API" "$VERIFY_TIMEOUT"
  exit 0
fi
deadline=$(( $(date +%s) + VERIFY_TIMEOUT ))
while :; do
  # The header comes from a file descriptor so the token is neither printed nor in the process list.
  report="$(curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$SGA_ADMIN_TOKEN") "$API/v1/admin/devices" \
    | python3 -c '
import json, sys
from datetime import UTC, datetime, timedelta
minutes = float(sys.argv[1])
now = datetime.now(UTC)
stale = 0
away = []
for d in json.load(sys.stdin):
    seen = d.get("last_seen")
    if d.get("revoked") or d.get("revoked_at") or not seen:
        continue
    when = datetime.fromisoformat(seen.replace("Z", "+00:00"))
    if now - when > timedelta(hours=24):
        continue  # long gone (old test devices)
    if now - when > timedelta(minutes=minutes):
        away.append("%s (last seen %s)" % (d["device_id"], seen[:19]))
        continue
    ok = bool(d.get("policy_current"))
    stale += not ok
    print("  %-5s %-16s last seen %s" % ("ok" if ok else "STALE", d["device_id"], seen[:19]))
for a in away:
    print("  away  " + a + ": not checked, picks the policy up when its sensor reconnects")
print("STALE=%d" % stale)
' "$ACTIVE_MINUTES")" || { echo "could not read devices from $API" >&2; exit 1; }
  if [[ "$report" == *"STALE=0" ]]; then
    printf '%s\n' "${report%STALE=*}"
    echo "deployed $commit (backup sga.db.$LABEL)"
    exit 0
  fi
  if (( $(date +%s) >= deadline )); then
    printf '%s\n' "${report%STALE=*}"
    echo "some devices still run the old policy after ${VERIFY_TIMEOUT}s (check their sensor logs)" >&2
    exit 1
  fi
  sleep 10
done

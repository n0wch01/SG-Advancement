#!/usr/bin/env bash
# Real Claude Code verification lab on this Mac (docs/claude-code-live.md, 2026-11-17 decision 1-C).
#
#   scripts/cc_live_lab.sh up            # throwaway control plane + sensor daemon + hook in an isolated config
#   CLAUDE_CONFIG_DIR="$PWD/data/cc-live/config" claude   # run from data/cc-live/project; you log in yourself
#   scripts/cc_live_lab.sh check         # side effects (files) and what the control plane recorded
#   scripts/cc_live_lab.sh daemon-down   # failure case: stop the sensor daemon (the hook falls back)
#   scripts/cc_live_lab.sh daemon-up
#   scripts/cc_live_lab.sh down          # stop everything (files stay under data/cc-live for the record)
#
# Everything lives under data/cc-live (git-ignored). The real ~/.claude and any real control plane are
# never touched: Claude Code reads settings, and keys its Keychain login, by CLAUDE_CONFIG_DIR.
# The admin token is generated here, kept in data/cc-live/admin-token (0600) and never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/data/cc-live"
PORT="${SGA_LAB_PORT:-8765}"
SERVER="http://127.0.0.1:$PORT"
CONFIG="$LAB/config"
HOME_DIR="$LAB/sga-home"
PROJECT="$LAB/project"
USER_ID="lab-user"

die() { echo "cc_live_lab: $*" >&2; exit 1; }
token() { cat "$LAB/admin-token"; }
api() { curl -fsS -H "Authorization: Bearer $(token)" "$SERVER$1"; }
# The lab's own processes, by their command lines (uv run starts a child; a saved $! is only the wrapper).
pattern() { case "$1" in server) echo "sga-server --port $PORT" ;; daemon) echo "sga-sensor --home $HOME_DIR run" ;; esac; }
running() { pgrep -f "$(pattern "$1")" >/dev/null; }
stop() { pkill -f "$(pattern "$1")" && echo "stopped $1"; rm -f "$LAB/$1.pid"; }

start_daemon() {
  running daemon && return 0
  # CLAUDE_CONFIG_DIR: the daemon's config check looks at the same settings file Claude Code reads.
  (cd "$ROOT" && CLAUDE_CONFIG_DIR="$CONFIG" nohup uv run sga-sensor --home "$HOME_DIR" run --user "$USER_ID" \
      >"$LAB/daemon.log" 2>&1 & echo $! >"$LAB/daemon.pid")
  for _ in $(seq 1 50); do [[ -S "$HOME_DIR/sga.sock" ]] && return 0; sleep 0.2; done
  die "sensor daemon did not start (see $LAB/daemon.log)"
}

up() {
  [[ "$CONFIG" != "$HOME/.claude" ]] || die "refusing to use the real ~/.claude"
  mkdir -p "$LAB" "$CONFIG" "$HOME_DIR" "$PROJECT"
  chmod 700 "$LAB"
  if [[ ! -f "$LAB/admin-token" ]]; then
    (umask 077; uv run python -c "import secrets; print(secrets.token_urlsafe(32))" >"$LAB/admin-token")
  fi
  if ! running server; then
    (cd "$ROOT" && SGA_ADMIN_TOKEN="$(token)" SGA_DB_URL="sqlite:///$LAB/cp.db" \
      SGA_SIGNING_KEY="$LAB/cp-key.pem" SGA_RULES_DIR="$ROOT/rules" SGA_AUTO_VERIFY=0 \
      nohup uv run sga-server --port "$PORT" >"$LAB/server.log" 2>&1 & echo $! >"$LAB/server.pid")
    for _ in $(seq 1 50); do curl -fsS "$SERVER/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
    curl -fsS "$SERVER/healthz" >/dev/null || die "control plane did not start (see $LAB/server.log)"
  fi
  if [[ ! -f "$HOME_DIR/credentials.json" ]]; then
    local t
    t="$(cd "$ROOT" && SGA_ADMIN_TOKEN="$(token)" \
      uv run sga-server device --server "$SERVER" token --label cc-live 2>/dev/null)"
    [[ -n "$t" ]] || die "could not create an enrollment token (see $LAB/server.log)"
    (cd "$ROOT" && SGA_ENROLL_TOKEN="$t" uv run sga-sensor --home "$HOME_DIR" enroll --server "$SERVER" \
      --device-id cc-live-mac >/dev/null)
  fi
  start_daemon
  (cd "$ROOT" && CLAUDE_CONFIG_DIR="$CONFIG" uv run sga-sensor --home "$HOME_DIR" claude-code install \
    --user "$USER_ID")
  # The test project: files whose survival is the evidence. The .env holds fake values only.
  mkdir -p "$PROJECT/victim/sub"
  echo "keep me" >"$PROJECT/victim/sub/keep.txt"
  echo "keep me too" >"$PROJECT/victim/plain.txt"
  printf 'FAKE_API_TOKEN=not-a-real-secret\n' >"$PROJECT/.env"
  printf '# cc-live test project\nA throwaway repository for SG-Advance live checks.\n' >"$PROJECT/README.md"
  [[ -d "$PROJECT/.git" ]] || git -C "$PROJECT" init -q
  cat <<EOF

Ready. In a new terminal:
  cd "$PROJECT"
  CLAUDE_CONFIG_DIR="$CONFIG" claude
Log in when asked (this login is stored for $CONFIG only). Then follow docs/claude-code-live.md.
After each scenario: scripts/cc_live_lab.sh check
EOF
}

check() {
  echo "## files (the evidence)"
  for f in victim/sub/keep.txt victim/plain.txt .env; do
    if [[ -e "$PROJECT/$f" ]]; then echo "  present  $f"; else echo "  GONE     $f"; fi
  done
  echo "## sensor"
  if running daemon; then echo "  daemon running"; else echo "  daemon NOT running"; fi
  (cd "$ROOT" && uv run sga-sensor --home "$HOME_DIR" sync >/dev/null 2>&1 || true)
  echo "## recent findings (rule · decision · stage · confirmation)"
  api "/v1/admin/findings?limit=20" | uv run python -c '
import json, sys
for f in json.load(sys.stdin):
    r = f.get("response") or {}
    print("  ", f["ts"][11:19], f["rule_id"], "·", r.get("decision"), "·", r.get("stage"), "·", r.get("confirmation"))
'
  echo "## recent tool calls and approvals"
  api "/v1/admin/events?limit=30" | uv run python -c '
import json, sys
for e in json.load(sys.stdin):
    p, l = e["payload"], e.get("labels", {})
    if p["kind"] in ("tool.call", "approval.resolved", "tool.result"):
        what = (p.get("arguments") or {}).get("command") or p.get("decision") or ""
        extra = " ".join(f"{k}={v}" for k, v in l.items() if k in ("sga_act_parse", "sga_act_destroy", "sga_verdict", "sga_approval_inferred"))
        print("  ", e["ts"][11:19], p["kind"], p.get("tool", ""), str(what)[:70], extra)
'
}

down() {
  for p in daemon server; do
    if running "$p"; then stop "$p"; fi
  done
}

case "${1:-}" in
  up) up ;;
  check) check ;;
  daemon-down) if running daemon; then stop daemon; fi ;;
  daemon-up) start_daemon && echo "daemon running" ;;
  down) down ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac

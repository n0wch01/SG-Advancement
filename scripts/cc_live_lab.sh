#!/usr/bin/env bash
# Real Claude Code verification lab on this Mac (docs/claude-code-live.md, 2026-11-17 decision 1-C).
#
#   scripts/cc_live_lab.sh up            # throwaway control plane + sensor daemon + hook in an isolated config
#   scripts/cc_live_lab.sh run           # enter Claude Code with isolated settings and updates disabled
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
RECEIVER_PORT="${SGA_LAB_RECEIVER_PORT:-8766}"
SERVER="http://127.0.0.1:$PORT"
CONFIG="$LAB/config"
HOME_DIR="$LAB/sga-home"
PROJECT="$LAB/project"
USER_ID="lab-user"
PYTHON="$ROOT/.venv/bin/python"
SENSOR="$ROOT/.venv/bin/sga-sensor"
SERVER_EXE="$ROOT/.venv/bin/sga-server"

die() { echo "cc_live_lab: $*" >&2; exit 1; }
token() { cat "$LAB/admin-token"; }
api() { curl -fsS -H "Authorization: Bearer $(token)" "$SERVER$1"; }
process() { "$PYTHON" "$ROOT/scripts/cc_lab_process.py" "$1" --lab "$LAB" --name "$2" "${@:3}"; }
running() { process status "$1"; }
stop() { process stop "$1"; }

start_daemon() {
  running daemon && return 0
  # CLAUDE_CONFIG_DIR: the daemon's config check looks at the same settings file Claude Code reads.
  CLAUDE_CONFIG_DIR="$CONFIG" process start daemon --cwd "$ROOT" -- \
    "$SENSOR" --home "$HOME_DIR" run --user "$USER_ID" --classifier "$ROOT/data/models/protectai-v2"
  for _ in $(seq 1 50); do
    running daemon || die "sensor daemon exited (see $LAB/daemon.log)"
    process ready daemon --socket "$HOME_DIR/sga.sock" && return 0
    sleep 0.2
  done
  die "sensor daemon did not start (see $LAB/daemon.log)"
}

start_receiver() {
  process start receiver --cwd "$ROOT" --port "$RECEIVER_PORT" -- \
    "$PYTHON" "$ROOT/scripts/cc_lab_receiver.py" --port "$RECEIVER_PORT" --receipts "$LAB/receipts.jsonl"
  for _ in $(seq 1 50); do
    running receiver || die "receiver exited (see $LAB/receiver.log)"
    curl -fsS "http://127.0.0.1:$RECEIVER_PORT/healthz" >/dev/null && return 0
    sleep 0.1
  done
  die "receiver did not start"
}

fixtures() {
  mkdir -p "$PROJECT/victim/sub"
  echo "keep me" >"$PROJECT/victim/sub/keep.txt"
  echo "keep me too" >"$PROJECT/victim/plain.txt"
  printf 'FAKE_API_TOKEN=not-a-real-secret\n' >"$PROJECT/.env"
  printf '# cc-live test project\nA throwaway repository for SG-Advance live checks.\n' >"$PROJECT/README.md"
  [[ -d "$PROJECT/.git" ]] || git -C "$PROJECT" init -q
  touch "$PROJECT/.sga-lab-initialized"
}

publish() {
  running server || die "the lab does not own a running server"
  curl -fsS -X POST -H "Authorization: Bearer $(token)" "$SERVER/v1/admin/policy/reload" >/dev/null
  "$SENSOR" --home "$HOME_DIR" sync
}

claude_run() {
  local executable="${SGA_CLAUDE_BIN:-$(command -v claude)}"
  (cd "$PROJECT" && DISABLE_AUTOUPDATER=1 CLAUDE_CONFIG_DIR="$CONFIG" "$executable" "$@")
}

codex_run() {
  local executable="${SGA_CODEX_BIN:-$(command -v codex)}"
  (cd "$PROJECT" && CODEX_HOME="$ROOT/data/codex-live/config" "$executable" --no-daemon "$@")
}

up() {
  [[ "$CONFIG" != "$HOME/.claude" ]] || die "refusing to use the real ~/.claude"
  [[ -x "$PYTHON" && -x "$SENSOR" && -x "$SERVER_EXE" ]] || die "install the project environment first"
  mkdir -p "$LAB" "$CONFIG" "$HOME_DIR" "$PROJECT"
  chmod 700 "$LAB"
  if [[ ! -f "$LAB/admin-token" ]]; then
    (umask 077; "$PYTHON" -c "import secrets; print(secrets.token_urlsafe(32))" >"$LAB/admin-token")
  fi
  if ! running server; then
    SGA_ADMIN_TOKEN="$(token)" SGA_DB_URL="sqlite:///$LAB/cp.db" \
      SGA_SIGNING_KEY="$LAB/cp-key.pem" SGA_RULES_DIR="$ROOT/rules" SGA_AUTO_VERIFY=0 \
      process start server --cwd "$ROOT" --port "$PORT" -- "$SERVER_EXE" --port "$PORT"
    for _ in $(seq 1 50); do curl -fsS "$SERVER/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
    curl -fsS "$SERVER/healthz" >/dev/null || die "control plane did not start (see $LAB/server.log)"
  fi
  api "/v1/admin/devices" >/dev/null || die "the server does not accept this lab's identity"
  if [[ ! -f "$HOME_DIR/credentials.json" ]]; then
    local t
    t="$(cd "$ROOT" && SGA_ADMIN_TOKEN="$(token)" \
      "$SERVER_EXE" device --server "$SERVER" token --label cc-live 2>/dev/null)"
    [[ -n "$t" ]] || die "could not create an enrollment token (see $LAB/server.log)"
    (cd "$ROOT" && SGA_ENROLL_TOKEN="$t" "$SENSOR" --home "$HOME_DIR" enroll --server "$SERVER" \
      --device-id cc-live-mac >/dev/null)
  fi
  (cd "$ROOT" && CLAUDE_CONFIG_DIR="$CONFIG" "$SENSOR" --home "$HOME_DIR" claude-code install \
    --user "$USER_ID")
  start_daemon
  start_receiver
  [[ -f "$PROJECT/.sga-lab-initialized" ]] || fixtures
  cat <<EOF

Ready. In a new terminal:
  "$ROOT/scripts/cc_live_lab.sh" run
Log in when asked (this login is stored for $CONFIG only). Then follow docs/claude-code-live.md.
After each scenario: scripts/cc_live_lab.sh check
Receiver: http://127.0.0.1:$RECEIVER_PORT/collect (receipts: $LAB/receipts.jsonl)
To publish edited rules to the lab DB: scripts/cc_live_lab.sh publish
To reset fake fixture files explicitly: scripts/cc_live_lab.sh reset-fixtures
EOF
}

check() {
  echo "## files (the evidence)"
  for f in victim/sub/keep.txt victim/plain.txt .env; do
    if [[ -e "$PROJECT/$f" ]]; then echo "  present  $f"; else echo "  GONE     $f"; fi
  done
  echo "## HTTP receipts (no request body is stored)"
  "$PYTHON" - "$LAB/receipts.jsonl" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
rows = [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []
print("  total:", len(rows))
for row in rows[-10:]:
    print("  ", row["ts"], row["path"], row["bytes"], row["sha256"][:12])
PY
  echo "## sensor"
  if running daemon; then echo "  daemon running"; else echo "  daemon NOT running"; fi
  (cd "$ROOT" && "$SENSOR" --home "$HOME_DIR" sync >/dev/null 2>&1 || true)
  echo "## recent findings (rule · decision · stage · confirmation)"
  api "/v1/admin/findings?limit=20" | "$PYTHON" -c '
import json, sys
for f in json.load(sys.stdin):
    r = f.get("response") or {}
    print("  ", f["ts"][11:19], f["rule_id"], "·", r.get("decision"), "·", r.get("stage"), "·", r.get("confirmation"))
'
  echo "## recent tool calls and approvals"
  api "/v1/admin/events?limit=30" | "$PYTHON" -c '
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
  for p in daemon receiver server; do
    stop "$p"
  done
}

case "${1:-}" in
  up) up ;;
  check) check ;;
  daemon-down) if running daemon; then stop daemon; fi ;;
  daemon-up) start_daemon && echo "daemon running" ;;
  publish) publish ;;
  reset-fixtures) fixtures ;;
  run) shift; claude_run "$@" ;;
  codex-run) shift; codex_run "$@" ;;
  down) down ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac

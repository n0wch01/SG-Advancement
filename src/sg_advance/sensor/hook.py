"""Claude Code hook entry point (M6): ``sga-hook [--home H] [--user U]``, run by Claude Code for
PreToolUse, PostToolUse, UserPromptSubmit, SessionStart and SessionEnd (hook JSON on stdin).

Claude Code starts this once per hook, so the usual path imports nothing heavy: it maps the hook
input to an ``AgentEvent`` dict and asks the sensor daemon over the local API (unix socket, or the
loopback TCP endpoint on Windows), the same API the OpenClaw plugin uses. Answers:

- ``tool.call`` (PreToolUse): block → ``permissionDecision: deny``; require_approval → ``ask``
  (Claude Code's own permission prompt); security_approval → wait for security, then allow or
  deny; allow → no output, so Claude Code's normal permission rules still apply (a hook never
  widens what the person allowed).
- ``prompt.user`` (UserPromptSubmit): a blocking verdict stops the prompt (exit 2).
- everything else: recorded, never blocks.

Daemon unreachable: the cached signed policy judges here (stateless rules only) and the event is
spooled with ``labels.sga_verdict = degraded``. No policy either: read-only tools pass, anything
else goes to Claude Code's prompt (``ask``), the same risk tiers as the OpenClaw plugin.
The hook settings use ``onFailure: block`` for PreToolUse, so a crashed or missing hook blocks.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DAEMON_TIMEOUT = 3.0
READ_ONLY_TOOLS = {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoRead", "TodoWrite"}
PREVIEW_MAX = 4000
DEFAULT_HOME = Path("~/.sg-advance")


# ── hook input → AgentEvent (plain dict; the daemon validates) ──────────────


def _provider(tool: str) -> dict[str, Any]:
    """``mcp__<server>__<tool>`` is an MCP tool; everything else is built in."""
    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        if len(parts) == 3 and parts[1]:
            return {"kind": "mcp", "mcp_server": parts[1]}
    return {"kind": "builtin"}


def _preview(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text[:PREVIEW_MAX]


def hook_event(inp: dict[str, Any], *, user_id: str, hostname: str | None) -> dict[str, Any] | None:
    name = inp.get("hook_event_name")
    tool = str(inp.get("tool_name") or "unknown")
    call_id = str(inp.get("tool_use_id") or f"cc-{uuid.uuid4().hex[:12]}")
    if name == "PreToolUse":
        args = inp.get("tool_input")
        payload: dict[str, Any] = {
            "kind": "tool.call",
            "call_id": call_id,
            "tool": tool,
            "provider": _provider(tool),
            "arguments": args if isinstance(args, dict) else {"input": args},
        }
    elif name in ("PostToolUse", "PostToolUseFailure"):
        ok = name == "PostToolUse"
        response = inp.get("tool_response") if ok else inp.get("error", inp.get("tool_response"))
        payload = {
            "kind": "tool.result",
            "call_id": call_id,
            "tool": tool,
            "provider": _provider(tool),
            "ok": ok,
            "output_preview": _preview(response) if response is not None else None,
        }
        if not ok:
            payload["error"] = _preview(response)[:500] if response is not None else "failed"
    elif name == "UserPromptSubmit":
        payload = {"kind": "prompt.user", "text": str(inp.get("prompt") or "")}
    elif name == "SessionStart":
        payload = {
            "kind": "session.start",
            "reason": inp.get("source"),
            "permission_mode": inp.get("permission_mode"),
        }
    elif name == "SessionEnd":
        payload = {"kind": "session.end", "reason": inp.get("reason")}
    else:
        return None
    labels = {"sga_source": "claude_code_hook", "claude_code.hook": str(name)}
    if isinstance(inp.get("permission_mode"), str):
        labels["claude_code.permission_mode"] = inp["permission_mode"]
    agent: dict[str, Any] = {"type": "claude_code", "session_id": str(inp.get("session_id") or "unknown")}
    if isinstance(inp.get("cwd"), str):
        agent["cwd"] = inp["cwd"]
    return {
        "ts": datetime.now(UTC).isoformat(),
        "endpoint": {"device_id": "pending", "hostname": hostname},
        "principal": {"user_id": user_id},
        "agent": agent,
        "source": {"sensor": "claude_code_hook"},
        "payload": payload,
        "labels": labels,
    }


# ── talking to the daemon ───────────────────────────────────────────────────


def _connect(home: Path, timeout: float) -> tuple[socket.socket, str | None]:
    endpoint = home / "sga-api.json"
    sock_path = Path(os.environ["SGA_SOCKET"]) if os.environ.get("SGA_SOCKET") else home / "sga.sock"
    if sys.platform == "win32" or (endpoint.exists() and not sock_path.exists()):
        ep = json.loads(endpoint.read_text("utf-8"))
        sock = socket.create_connection((ep.get("host") or "127.0.0.1", int(ep["port"])), timeout=timeout)
        return sock, str(ep["token"])
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
    sock.settimeout(timeout)
    sock.connect(str(sock_path))
    return sock, None


def ask(home: Path, msg: dict[str, Any], timeout: float = DAEMON_TIMEOUT) -> dict[str, Any]:
    sock, token = _connect(home, timeout)
    try:
        if token is not None:
            msg = msg | {"auth": token}
        sock.sendall((json.dumps(msg) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf or b"{}")
    finally:
        sock.close()


def degraded(home: Path, event: dict[str, Any]) -> dict[str, Any]:
    """No daemon: judge with the cached signed policy and spool the event for later."""
    from ..schema import AgentEvent
    from .core import Sensor
    from .plugin_api import CLAUDE_CODE_HOOK, plugin_response
    from .state import SensorHome

    sensor = Sensor(SensorHome(home))
    if not sensor.load_cached_policy():
        raise RuntimeError("no cached policy")
    ev = AgentEvent.model_validate(event | {"labels": event["labels"] | {"sga_verdict": "degraded"}})
    result = sensor.evaluate(ev)
    if ev.kind.value == "tool.call":
        response, enforcement = plugin_response(result.verdict, CLAUDE_CODE_HOOK)
    else:
        response, enforcement = {"ok": True, "decision": "allow"}, None
    sensor.record(result, enforcement)
    return response


def fallback(event: dict[str, Any]) -> dict[str, Any]:
    """Nothing to judge with: read-only tools pass, the rest goes to Claude Code's prompt."""
    p = event["payload"]
    if p["kind"] != "tool.call" or p["tool"] in READ_ONLY_TOOLS:
        return {"ok": True, "decision": "allow"}
    return {
        "ok": True,
        "decision": "approve",
        "reason": f"SG-Advance sensor unavailable: approve this {p['tool']} call only if you expected it",
    }


def judge(home: Path, event: dict[str, Any]) -> dict[str, Any]:
    try:
        r = ask(home, {"op": "event", "event": event})
        if r.get("ok"):
            if r.get("decision") == "hold":
                wait = float(r.get("wait_ms") or 300_000) / 1000 + 15
                try:
                    return ask(home, {"op": "await_hold", "hold_id": r.get("hold_id")}, timeout=wait)
                except (OSError, ValueError) as e:
                    return {
                        "ok": True,
                        "decision": "block",
                        "reason": f"SG-Advance: 보안팀 승인 대기 중 센서 연결이 끊겨 차단 ({e})",
                    }
            return r
    except (OSError, ValueError, KeyError):
        pass
    try:
        return degraded(home, event)
    except Exception:  # noqa: BLE001 - not enrolled, no policy, broken cache: fall back to risk tiers
        return fallback(event)


# ── answer Claude Code ──────────────────────────────────────────────────────


def respond(hook: str, verdict: dict[str, Any]) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) for Claude Code."""
    decision = verdict.get("decision")
    reason = str(verdict.get("reason") or "SG-Advance policy")
    if hook == "PreToolUse" and decision in ("block", "approve"):
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if decision == "block" else "ask",
                "permissionDecisionReason": reason,
            }
        }
        return 0, json.dumps(out, ensure_ascii=False), ""
    if hook == "UserPromptSubmit" and decision == "block":
        return 2, "", reason  # exit 2 stops the prompt; stderr is shown
    return 0, "", ""


def main(argv: list[str] | None = None) -> int:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(
        prog="sga-hook", description="SG-Advance hook for Claude Code (stdin: hook JSON)"
    )
    ap.add_argument("--home", type=Path, default=None)
    ap.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser())
    ap.add_argument("--socket", help="daemon socket when it is not <home>/sga.sock (sga-sensor run --socket)")
    args = ap.parse_args(argv)
    if args.socket:
        os.environ["SGA_SOCKET"] = args.socket
    home = (args.home or Path(os.environ.get("SGA_HOME") or DEFAULT_HOME)).expanduser()
    started = time.monotonic()
    try:
        inp = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        print("SG-Advance hook: input is not JSON", file=sys.stderr)
        return 1  # non-blocking error: Claude Code's onFailure decides
    event = hook_event(inp, user_id=args.user, hostname=socket.gethostname())
    if event is None:
        return 0
    code, out, err = respond(str(inp.get("hook_event_name")), judge(home, event))
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    if os.environ.get("SGA_HOOK_DEBUG"):
        print(f"sga-hook {inp.get('hook_event_name')} {time.monotonic() - started:.3f}s", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

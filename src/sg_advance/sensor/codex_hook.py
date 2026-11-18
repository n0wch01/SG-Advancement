"""Direct Codex CLI hook translation. Detection, transport and signed-cache fallback stay shared."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import hook
from .envelope import envelope

EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd")


def required(inp: dict[str, Any], key: str) -> str:
    value = inp.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


def hook_event(inp: dict[str, Any], *, user_id: str, hostname: str | None) -> dict[str, Any] | None:
    name = inp.get("hook_event_name")
    if name not in EVENTS:
        return None
    session = required(inp, "session_id")
    labels = {"sga_source": "codex_cli_hook", "codex.hook": str(name)}
    agent: dict[str, Any] = {"type": "codex_cli", "session_id": session, "agent_id": "main"}
    for source, target in (("cwd", "cwd"), ("model", "model"), ("turn_id", "run_id")):
        if isinstance(inp.get(source), str):
            agent[target] = inp[source]
    if isinstance(inp.get("permission_mode"), str):
        labels["sga_permission_mode"] = inp["permission_mode"]
        labels["codex.permission_mode"] = inp["permission_mode"]
    if name in ("PreToolUse", "PostToolUse"):
        tool, call_id = required(inp, "tool_name"), required(inp, "tool_use_id")
        original = inp.get("tool_input")
        labels["sga_input_digest"] = hook.input_digest(original)
        if name == "PreToolUse":
            if not isinstance(original, dict):
                raise ValueError("tool_input must be an object")
            args = dict(original)
            if tool == "apply_patch" and isinstance(args.get("command"), str):
                args["input"] = args.pop("command")
            payload: dict[str, Any] = {
                "kind": "tool.call", "call_id": call_id, "tool": tool,
                "provider": hook._provider(tool), "arguments": args,
            }
        else:
            response = inp.get("tool_response")
            text = hook.inspection_text(tool, response) if response is not None else ""
            payload = {
                "kind": "tool.result", "call_id": call_id, "tool": tool,
                "provider": hook._provider(tool), "output_preview": text[:hook.INSPECT_MAX],
                "output_bytes": len(text.encode()),
            }
            # This event also fires on non-zero exits; returning output alone isn't proof of success.
            labels["codex.result_status"] = "not_reported"
            if isinstance(response, dict) and isinstance(response.get("exit_code"), int):
                payload["ok"] = response["exit_code"] == 0
                labels["codex.result_status"] = "reported"
            if len(text) > hook.INSPECT_MAX:
                labels["sga_result_uninspected"] = "too_large"
    elif name == "UserPromptSubmit":
        payload = {"kind": "prompt.user", "text": str(inp.get("prompt") or "")}
    else:
        payload = {
            "kind": "session.start" if name == "SessionStart" else "session.end",
            "reason": inp.get("source") if name == "SessionStart" else inp.get("reason"),
        }
        if name == "SessionStart" and isinstance(inp.get("permission_mode"), str):
            payload["permission_mode"] = inp["permission_mode"]
    return envelope(sensor="codex_cli_hook", agent=agent, payload=payload, hostname=hostname,
                    user_id=user_id, labels=labels, ts=datetime.now(UTC).isoformat())  # fmt: skip


def respond(name: str, verdict: dict[str, Any]) -> tuple[int, str, str]:
    decision = verdict.get("decision")
    reason = str(verdict.get("reason") or "SG-Advance policy")
    if name == "PreToolUse" and decision in ("block", "approve"):
        if decision == "approve":
            reason = f"SG-Advance: this Codex path cannot confirm user approval; denied. {reason}"
        return 0, json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason,
        }}), ""
    if name == "PostToolUse" and decision == "withhold":
        return 0, json.dumps({"decision": "block", "reason": reason, "hookSpecificOutput": {
            "hookEventName": "PostToolUse", "additionalContext": reason,
        }}), ""
    if name == "UserPromptSubmit" and decision == "block":
        return 0, json.dumps({"continue": False, "stopReason": reason, "systemMessage": reason}), ""
    return 0, "", ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=None)
    parser.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser())
    args = parser.parse_args(argv)
    home = (args.home or Path(os.environ.get("SGA_HOME") or hook.DEFAULT_HOME)).expanduser()
    try:
        inp = json.loads(hook.read_stdin() or "{}")
        if not isinstance(inp, dict):
            raise ValueError("hook input must be an object")
        event = hook_event(inp, user_id=args.user, hostname=socket.gethostname())
        if event is None:
            return 0
        code, out, err = respond(str(inp["hook_event_name"]), hook.judge(home, event))
        if out:
            hook.emit(sys.stdout, out)
        if err:
            hook.emit(sys.stderr, err)
        return code
    except Exception as e:
        with contextlib.suppress(OSError, ValueError):
            hook.emit(sys.stderr, f"SG-Advance Codex hook failed ({type(e).__name__}); denied")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

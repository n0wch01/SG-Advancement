"""Put the SG-Advance hook into Claude Code's settings (M6), and report where it is.

Decision 2026-11-13 ("둘 다 + 탐지"):

- **managed** (with administrator rights): a drop-in file in Claude Code's managed settings
  directory (``managed-settings.d/sg-advance.json``). Users cannot remove managed hooks, and
  bypass-permissions mode is switched off. This is how a company deploys it (MDM / installer).
- **user** (no rights): merged into ``~/.claude/settings.json``. Works the same, but the person can
  delete it; the sensor's check reports that (``claude-code-guard-hook-*`` rules).

The hook runs as an exec-form command (no shell: on Windows it must be a real .exe, which
``sga-hook.exe`` in the sensor's venv is). PreToolUse uses ``onFailure: block`` so a missing or
broken hook blocks tool calls instead of silently allowing them, and a timeout long enough for a
security-approval wait.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

DROP_IN = "sg-advance.json"
HOOK_EXE = "sga-hook"
EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "SessionEnd")
PRE_TOOL_TIMEOUT = 360  # seconds: covers a 5-minute security approval wait plus margin
OTHER_TIMEOUT = 15


def managed_dir(platform: str = sys.platform) -> Path:
    if platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.d")
    if platform == "win32":
        return Path("C:/Program Files/ClaudeCode/managed-settings.d")
    return Path("/etc/claude-code/managed-settings.d")


def user_settings(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".claude" / "settings.json"


def hook_executable() -> str:
    """``sga-hook`` next to the running interpreter (the sensor's venv), else on PATH."""
    scripts = Path(sys.executable).parent
    for name in (f"{HOOK_EXE}.exe", HOOK_EXE):
        if (scripts / name).exists():
            return str(scripts / name)
    found = shutil.which(HOOK_EXE)
    if not found:
        raise RuntimeError("sga-hook executable not found next to the sensor")
    return found


def hooks_block(exe: str, sga_home: Path, user: str) -> dict[str, Any]:
    args = ["--home", str(sga_home), "--user", user]
    hooks: dict[str, Any] = {}
    for event in EVENTS:
        handler: dict[str, Any] = {"type": "command", "command": exe, "args": args}
        if event == "PreToolUse":
            handler |= {"timeout": PRE_TOOL_TIMEOUT, "onFailure": "block"}
        else:
            handler |= {"timeout": OTHER_TIMEOUT}
        entry: dict[str, Any] = {"hooks": [handler]}
        if event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            entry["matcher"] = "*"
        hooks[event] = [entry]
    return hooks


def managed_document(exe: str, sga_home: Path, user: str) -> dict[str, Any]:
    """The company's drop-in: the hook, and no bypass-permissions mode."""
    return {
        "hooks": hooks_block(exe, sga_home, user),
        "permissions": {"disableBypassPermissionsMode": "disable"},
    }


def _is_ours(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    return Path(str(handler.get("command", ""))).stem.lower() == HOOK_EXE


def merge_user(settings: dict[str, Any], exe: str, sga_home: Path, user: str) -> dict[str, Any]:
    """Our hooks added to someone's settings, theirs kept; re-running replaces ours only."""
    out = dict(settings)
    hooks = {k: list(v) for k, v in (out.get("hooks") or {}).items() if isinstance(v, list)}
    for event, entries in hooks_block(exe, sga_home, user).items():
        kept = []
        for entry in hooks.get(event, []):
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                rest = [h for h in entry["hooks"] if not _is_ours(h)]
                if rest:
                    kept.append(entry | {"hooks": rest})
            else:
                kept.append(entry)
        hooks[event] = kept + entries
    out["hooks"] = hooks
    return out


def remove_user(settings: dict[str, Any]) -> dict[str, Any]:
    out = dict(settings)
    hooks: dict[str, Any] = {}
    for event, entries in (out.get("hooks") or {}).items():
        kept = []
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                rest = [h for h in entry["hooks"] if not _is_ours(h)]
                if rest:
                    kept.append(entry | {"hooks": rest})
            else:
                kept.append(entry)
        if kept:
            hooks[event] = kept
    if hooks:
        out["hooks"] = hooks
    else:
        out.pop("hooks", None)
    return out


def guard_state(doc: dict[str, Any] | None) -> bool:
    """True when this settings document runs our hook before tool calls."""
    for entry in ((doc or {}).get("hooks") or {}).get("PreToolUse") or []:
        if isinstance(entry, dict) and any(_is_ours(h) for h in entry.get("hooks") or []):
            return True
    return False


def _read(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def install(
    sga_home: Path,
    user: str,
    *,
    managed: bool,
    exe: str | None = None,
    platform: str = sys.platform,
    home: Path | None = None,
    dry_run: bool = False,
) -> str:
    exe = exe or hook_executable()
    if managed:
        path = managed_dir(platform) / DROP_IN
        doc = managed_document(exe, sga_home, user)
    else:
        path = user_settings(home)
        doc = merge_user(_read(path) or {}, exe, sga_home, user)
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if dry_run:
        return f"# {path}\n{text}"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not managed and path.exists():
        shutil.copy2(path, path.with_suffix(".json.sga-backup"))
    path.write_text(text, encoding="utf-8")
    where = (
        "managed settings (users cannot remove it)" if managed else "user settings (the user can remove it)"
    )
    return f"Claude Code hook installed in {where}: {path}"


def uninstall(*, platform: str = sys.platform, home: Path | None = None) -> list[str]:
    done = []
    drop_in = managed_dir(platform) / DROP_IN
    if drop_in.exists():
        drop_in.unlink()
        done.append(str(drop_in))
    path = user_settings(home)
    doc = _read(path)
    if doc is not None and guard_state(doc):
        path.write_text(json.dumps(remove_user(doc), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        done.append(str(path))
    return done


def status(*, platform: str = sys.platform, home: Path | None = None) -> dict[str, Any]:
    """Where the guard hook is, and the permission settings that matter (for the config check)."""
    managed_doc = _read(managed_dir(platform).parent / "managed-settings.json")
    drop_ins = sorted(managed_dir(platform).glob("*.json")) if managed_dir(platform).is_dir() else []
    managed_docs = [d for d in [managed_doc, *(_read(p) for p in drop_ins)] if d]
    user_doc = _read(user_settings(home))
    if any(guard_state(d) for d in managed_docs):
        guard = "managed"
    elif guard_state(user_doc):
        guard = "user"
    else:
        guard = "missing"
    perms = [(d.get("permissions") or {}) for d in managed_docs]
    bypass_disabled = any(p.get("disableBypassPermissionsMode") == "disable" for p in perms)
    default_mode = next(
        (p.get("defaultMode") for p in perms if p.get("defaultMode")),
        ((user_doc or {}).get("permissions") or {}).get("defaultMode"),
    )
    return {"guard": guard, "default_mode": default_mode, "bypass_disabled": bypass_disabled}

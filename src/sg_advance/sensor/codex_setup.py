"""Install the direct Codex hook in a user config layer; trust remains Codex's own review step."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

from .codex_hook import EVENTS

MODULE = "sg_advance.sensor.codex_hook"


def hooks_path(config_dir: Path | None = None) -> Path:
    root = config_dir or Path(os.environ.get("CODEX_HOME") or "~/.codex").expanduser()
    return root / "hooks.json"


def read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("hooks", {}), dict):
            raise ValueError("invalid hooks document")
        if any(not isinstance(entries, list) for entries in doc.get("hooks", {}).values()):
            raise ValueError("hook event entries must be lists")
        return doc
    except (ValueError, OSError) as e:
        raise RuntimeError(f"refusing to replace unreadable hooks: {path}") from e


def ours(handler: Any) -> bool:
    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    try:
        args = shlex.split(handler["command"])
    except ValueError:
        return False
    return len(args) >= 3 and args[1:3] == ["-m", MODULE]


def without_ours(doc: dict[str, Any]) -> dict[str, Any]:
    hooks = {}
    for event, entries in doc.get("hooks", {}).items():
        kept = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                handlers = [h for h in entry["hooks"] if not ours(h)]
                if handlers:
                    kept.append(entry | {"hooks": handlers})
            else:
                kept.append(entry)
        if kept:
            hooks[event] = kept
    return doc | {"hooks": hooks}


def install(
    home: Path, user: str, *, config_dir: Path | None = None, dry_run: bool = False,
    python: str = sys.executable, platform: str = sys.platform,
) -> str:
    if platform == "win32":
        raise RuntimeError("direct Codex hook installation is currently qualified for POSIX only")
    path = hooks_path(config_dir)
    doc = without_ours(read(path))
    command = shlex.join([python, "-m", MODULE, "--home", str(home.resolve()), "--user", user])
    hooks = doc["hooks"]
    for event in EVENTS:
        entry: dict[str, Any] = {"hooks": [{
            "type": "command", "command": command, "timeout": 3 if event == "SessionEnd" else 10,
        }]}
        if event in ("PreToolUse", "PostToolUse"):
            entry["matcher"] = ".*"
        hooks.setdefault(event, []).append(entry)
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    if dry_run:
        return f"# {path}\n{text}"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(".json.sga-backup"))
    path.write_text(text, encoding="utf-8")
    return f"Codex hook configured: {path}. Review and trust it with Codex /hooks before use."


def uninstall(config_dir: Path | None = None) -> bool:
    path = hooks_path(config_dir)
    if not path.exists():
        return False
    before = read(path)
    after = without_ours(before)
    if before == after:
        return False
    path.write_text(json.dumps(after, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True


def status(config_dir: Path | None = None) -> dict[str, Any]:
    path = hooks_path(config_dir)
    doc = read(path)
    configured = all(any(
        ours(h) for entry in doc.get("hooks", {}).get(event, []) if isinstance(entry, dict)
        for h in entry.get("hooks", [])
    ) for event in ("PreToolUse", "PostToolUse"))
    return {
        "path": str(path), "configured": configured, "trust": "check Codex /hooks", "scope": "user-removable",
    }

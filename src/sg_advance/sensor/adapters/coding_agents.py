"""Shadow AI discovery beyond OpenClaw (2026-11-13): the coding agents companies actually meet.

For each agent only its *own* traces are read: its executable on PATH (or the app bundle for
Cursor), its state directory, and the config files that list MCP servers:

| product | traces | MCP servers |
|---|---|---|
| claude-code | ``claude``, ``~/.claude/`` | ``~/.claude.json`` (``mcpServers``, per project too) |
| cursor | Cursor app, ``~/.cursor/`` | ``~/.cursor/mcp.json`` |
| codex | ``codex``, ``~/.codex/`` | ``~/.codex/config.toml`` (``[mcp_servers.*]``) |
| gemini | ``gemini``, ``~/.gemini/`` | ``~/.gemini/settings.json`` |

Managed means the SG-Advance control is in place: the Claude Code hook (managed or user settings,
``claude_code_setup.status``). The others have no SG-Advance control yet, so a configured install is
outside company control (their MCP traffic can still be routed through the MCP gateway).

Each MCP server becomes a ``McpServerRef`` with its route: ``gateway`` (URL under this sensor's MCP
gateway), ``direct`` (any other remote URL), ``local`` (stdio command), ``unknown`` (no gateway
configured here, so nothing can be said). Arguments, environment and query strings never leave the
endpoint: they are where MCP configs keep tokens. One exception: when a local server runs through a
package launcher (``npx -y postmark-mcp``), the package spec it runs is kept (``package``) so known
malicious packages can be matched (threat intelligence, KISA C1-5). Only that one argument, and only
if it has the shape of a package name.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

VersionOf = Callable[[str], str | None]


@dataclass(frozen=True)
class AgentSpec:
    product: str
    binaries: tuple[str, ...]
    state_dir: str
    apps: tuple[str, ...] = ()  # app bundles/executables relative to home or absolute


SPECS = (
    AgentSpec("claude-code", ("claude",), ".claude"),
    AgentSpec(
        "cursor",
        ("cursor",),
        ".cursor",
        apps=(
            "/Applications/Cursor.app",
            "Applications/Cursor.app",
            "AppData/Local/Programs/cursor/Cursor.exe",
            "/usr/share/cursor/cursor",
        ),
    ),
    AgentSpec("codex", ("codex",), ".codex"),
    AgentSpec("gemini", ("gemini",), ".gemini"),
)


def cli_version(exe: str) -> str | None:
    """``<exe> --version``, first token that looks like a version. Bounded: never blocks a scan long."""
    try:
        res = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for tok in (res.stdout or "").replace("(", " ").split():
        if tok[:1].isdigit() and "." in tok:
            return tok.strip(",")
    return None


def _clean_url(url: str) -> str:
    """scheme://host[:port]/path: no credentials, query or fragment (they can hold tokens)."""
    p = urlsplit(url)
    host = p.hostname or ""
    netloc = f"{host}:{p.port}" if p.port else host
    return urlunsplit((p.scheme, netloc, p.path, "", ""))


# Launchers that fetch and run a package named on the command line: (subcommand words, value flags).
# The package is the first non-flag argument after the subcommand; ``-p``/``--package``/``--from``
# name it explicitly. Anything else (a server's own flags, a token passed as an argument) is ignored.
_LAUNCHERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "npx": ((), ("-p", "--package")),
    "pnpx": ((), ()),
    "bunx": ((), ()),
    "uvx": ((), ("--from",)),
    "pipx": (("run",), ("--spec",)),
    "npm": (("exec", "x"), ("-p", "--package")),
    "pnpm": (("dlx",), ()),
    "yarn": (("dlx",), ("-p", "--package")),
}
# npm / PyPI package spec: optional @scope/, a name, an optional version or range after @ / ==.
# Launcher options that take a value that is not the package (skipped with their value).
_SKIP_VALUE = {"--with", "--python", "--registry", "--cache", "--index-url", "--pip-args"}
_PACKAGE = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*((@|==)[\w.^~<>=*+-]+)?$", re.I)


def launcher_package(command: str, args: Any) -> str | None:
    """The package a launcher command runs (``npx -y postmark-mcp@1.0.16`` → ``postmark-mcp@1.0.16``),
    or None if ``command`` is not a known launcher or no argument looks like a package."""
    spec = _LAUNCHERS.get(Path(command).name.lower().removesuffix(".cmd").removesuffix(".exe"))
    if spec is None or not isinstance(args, list):
        return None
    subcommands, value_flags = spec
    words = [a for a in args if isinstance(a, str)]
    if subcommands:
        if not words or words[0] not in subcommands:
            return None
        words = words[1:]
    found: str | None = None
    i = 0
    while i < len(words):
        w = words[i]
        if w == "--":
            break
        if w in value_flags and i + 1 < len(words):
            found = words[i + 1]
            break
        if w.split("=", 1)[0] in value_flags and "=" in w:
            found = w.split("=", 1)[1]
            break
        if w in _SKIP_VALUE:
            i += 2
            continue
        if w.startswith("-"):
            i += 1
            continue
        found = w
        break
    if found is None and "--" in words:  # npx -- pkg
        rest = words[words.index("--") + 1:]
        found = rest[0] if rest else None
    return found if found and len(found) <= 214 and _PACKAGE.match(found) else None


def server_ref(name: str, entry: Any, gateway_url: str | None, scope: str | None) -> dict[str, Any]:
    """One MCP server entry (any agent's format) → McpServerRef payload."""
    e = entry if isinstance(entry, dict) else {}
    url = e.get("url") or e.get("httpUrl") or e.get("serverUrl")
    kind = str(e.get("type") or e.get("transport") or "").lower()
    ref: dict[str, Any] = {"name": str(name), "scope": scope}
    if isinstance(url, str) and url:
        clean = _clean_url(url)
        ref |= {"transport": "sse" if kind == "sse" else "http", "url": clean}
        if gateway_url is None:
            ref["route"] = "unknown"
        else:
            ref["route"] = (
                "gateway" if clean.startswith(_clean_url(gateway_url).rstrip("/") + "/") else "direct"
            )
    elif isinstance(e.get("command"), str):
        ref |= {"transport": "stdio", "command": Path(e["command"]).name, "route": "local"}
        if pkg := launcher_package(e["command"], e.get("args")):
            ref["package"] = pkg
    else:
        ref |= {"transport": "unknown", "route": "unknown"}
    return ref


def _json(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def mcp_servers(product: str, home: Path, gateway_url: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(servers: Any, scope: str) -> None:
        if isinstance(servers, dict):
            out.extend(server_ref(n, e, gateway_url, scope) for n, e in servers.items())

    if product == "claude-code":
        doc = _json(home / ".claude.json") or {}
        add(doc.get("mcpServers"), "user")
        for proj in (doc.get("projects") or {}).values():
            if isinstance(proj, dict):
                add(proj.get("mcpServers"), "project")
    elif product == "cursor":
        add((_json(home / ".cursor" / "mcp.json") or {}).get("mcpServers"), "user")
    elif product == "gemini":
        add((_json(home / ".gemini" / "settings.json") or {}).get("mcpServers"), "user")
    elif product == "codex":
        try:
            doc = tomllib.loads((home / ".codex" / "config.toml").read_text("utf-8"))
        except (OSError, ValueError):
            doc = {}
        add(doc.get("mcp_servers"), "user")
    # The same server listed in several projects is one server.
    seen, unique = set(), []
    for r in out:
        key = (r["name"], r.get("url"), r.get("command"))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return sorted(unique, key=lambda r: (r["name"], r.get("url") or "", r.get("command") or ""))


def _find_app(spec: AgentSpec, home: Path, system: bool) -> Path | None:
    """App bundles in the user's home, and system-wide ones (``/Applications``) when ``system``."""
    for a in spec.apps:
        if a.startswith("/") and not system:
            continue
        p = Path(a) if a.startswith("/") else home / a
        if p.exists():
            return p
    return None


def describe_agent(
    spec: AgentSpec,
    home: Path,
    *,
    path_env: str | None,
    gateway_url: str | None,
    version_of: VersionOf,
    platform: str = sys.platform,
    check_apps: bool = True,
) -> dict[str, Any] | None:
    exe = next((w for b in spec.binaries if (w := shutil.which(b, path=path_env))), None)
    app = _find_app(spec, home, check_apps)
    state = home / spec.state_dir
    configured = state.is_dir() or (spec.product == "claude-code" and (home / ".claude.json").is_file())
    if exe is None and app is None and not configured:
        return None
    row: dict[str, Any] = {
        "product": spec.product,
        "instance": f"{spec.product}:{state}",
        "version": version_of(exe) if exe else None,
        "install_path": exe or (str(app) if app else None),
        "install_source": "app" if app and not exe else ("cli" if exe else None),
        "config_path": str(state) if configured else None,
        "configured": configured,
        "services": [],
        "watched": False,
        "mcp_servers": mcp_servers(spec.product, home, gateway_url) if configured else [],
    }
    if spec.product == "claude-code":
        from .. import claude_code_setup as cc

        guard = cc.status(platform=platform, home=home)["guard"]
        row["guard_plugin"] = "enabled" if guard in ("managed", "user") else "missing"
        row["managed"] = configured and guard in ("managed", "user")
        row["unmanaged_reasons"] = (
            [] if row["managed"] or not configured else ["no SG-Advance hook in Claude Code"]
        )
    else:
        row["managed"] = False
        row["unmanaged_reasons"] = (
            [f"no SG-Advance control for {spec.product} (route its MCP through the gateway)"]
            if configured
            else []
        )
    if not configured:
        row["unmanaged_reasons"] = ["not configured"]
    return row


def scan_agents(
    home: Path,
    *,
    path_env: str | None = None,
    gateway_url: str | None = None,
    version_of: VersionOf = cli_version,
    platform: str = sys.platform,
    check_apps: bool = True,
) -> list[dict[str, Any]]:
    rows = []
    for spec in SPECS:
        row = describe_agent(
            spec, home, path_env=path_env, gateway_url=gateway_url, version_of=version_of,
            platform=platform, check_apps=check_apps,
        )  # fmt: skip
        if row is not None:
            rows.append(row)
    return rows

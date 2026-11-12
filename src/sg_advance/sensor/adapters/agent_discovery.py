"""Agent install discovery (M5d): find OpenClaw installs on this endpoint, managed or not.

The company's supported path is the team gateway; a personal install on an employee PC is not
blocked but must be visible, with whether it meets the baseline. Every few minutes the sensor looks
for OpenClaw's *own* traces only, in the current user's home and the usual package locations:

- code: the ``openclaw`` executable on PATH and well-known global package dirs → version, path;
- instances: state dirs ``~/.openclaw`` and ``~/.openclaw-<profile>`` holding ``openclaw.json``;
- services: launchd / systemd user units whose name contains ``openclaw``;
- running: the instance's gateway port answers on 127.0.0.1 (no process listing, no other ports).

Each instance becomes one ``install.snapshot``: configured, gateway bind (loopback or network),
SG-Advance plugin state (``openclaw_config.guard_state``), whether this sensor watches it, and
``managed`` = configured + plugin enabled + watched. Code found without any state dir is reported as
one unconfigured install. Snapshots go out on first sight, on change, and once with
``present=false`` when an install disappears.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import socket
import sys
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...schema import AgentEvent, SensorType
from .base import AdapterContext
from .openclaw_config import GUARD_PLUGIN_ID, guard_state

log = logging.getLogger(__name__)

DEFAULT_PORT = 18789
DEFAULT_BIND = "loopback"  # OpenClaw's gateway.bind when unset
PACKAGE = "openclaw"
Probe = Callable[[str, int], bool]

# Global package locations besides whatever PATH resolves (another Node version, another manager).
GLOBAL_ROOTS = (
    "/opt/homebrew/lib/node_modules/openclaw",
    "/usr/local/lib/node_modules/openclaw",
    "/usr/lib/node_modules/openclaw",
)
HOME_ROOTS = (
    ".npm-global/lib/node_modules/openclaw",
    ".nvm/versions/node/*/lib/node_modules/openclaw",
    ".local/share/pnpm/global/*/node_modules/openclaw",
    "Library/pnpm/global/*/node_modules/openclaw",
    ".volta/tools/image/packages/openclaw/lib/node_modules/openclaw",
)


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _package_root(path: Path) -> Path | None:
    """The ``openclaw`` package directory containing ``path`` (the resolved executable)."""
    for d in [path, *path.parents][:4]:
        try:
            doc = json.loads((d / "package.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("name") == PACKAGE:
            return d
    return None


def _version(root: Path) -> str | None:
    try:
        v = json.loads((root / "package.json").read_text("utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        return None
    return v if isinstance(v, str) else None


def install_source(path: Path) -> str:
    p = path.as_posix()
    if "/.nvm/" in p:
        return "nvm"
    if "/pnpm/" in p:
        return "pnpm"
    if "/.volta/" in p:
        return "volta"
    if "/node_modules/" in p:
        return "npm-global"
    if p == "/app" or p.startswith("/app/") or p.startswith("/opt/"):
        return "app"
    return "other"


def find_code(home: Path, path_env: str | None = None, roots: Iterable[str] = GLOBAL_ROOTS) -> list[Path]:
    """OpenClaw package dirs, the one PATH runs first."""
    found: list[Path] = []
    exe = shutil.which("openclaw", path=path_env)
    candidates: list[Path] = []
    if exe:
        resolved = Path(os.path.realpath(exe))
        candidates.append(resolved.parent if resolved.is_file() else resolved)
    candidates += [Path(p) for p in roots]
    for pattern in HOME_ROOTS:
        candidates += sorted(home.glob(pattern))
    for c in candidates:
        root = _package_root(c) if c.exists() else None
        if root is not None and root.resolve() not in [f.resolve() for f in found]:
            found.append(root)
    return found


def find_instances(home: Path) -> list[Path]:
    """State dirs that were set up: ``~/.openclaw`` and ``~/.openclaw-<profile>`` with a config file."""
    dirs = [home / ".openclaw", *sorted(home.glob(".openclaw-*"))]
    return [d for d in dirs if (d / "openclaw.json").is_file()]


def find_services(home: Path, platform: str = sys.platform) -> list[str]:
    if platform == "darwin":
        units = home.glob("Library/LaunchAgents/*.plist")
    else:
        units = home.glob(".config/systemd/user/*.service")
    return sorted(u.stem for u in units if "openclaw" in u.name.lower())


def _read_config(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None  # JSON5 hand edits or a write in progress: report it as unreadable
    return doc if isinstance(doc, dict) else None


def _same(a: Path, b: Iterable[Path]) -> bool:
    try:
        ra = a.resolve()
        return any(ra == x.expanduser().resolve() for x in b)
    except OSError:
        return False


def describe(
    instance: Path | None,
    code: Path | None,
    *,
    services: list[str],
    watched_configs: Iterable[Path],
    probe: Probe,
    guard_id: str = GUARD_PLUGIN_ID,
) -> dict[str, Any]:
    """The install.snapshot payload (without kind/changed) for one instance, or unconfigured code."""
    out: dict[str, Any] = {
        "product": PACKAGE,
        "instance": str(instance or code),
        "version": _version(code) if code else None,
        "install_path": str(code) if code else None,
        "install_source": install_source(code) if code else None,
        "services": services,
    }
    reasons: list[str] = []
    if instance is None:
        out.update(configured=False, running=False, watched=False, managed=False)
        out["unmanaged_reasons"] = ["not configured"]
        return out
    cfg_path = instance / "openclaw.json"
    cfg = _read_config(cfg_path)
    gateway = (cfg or {}).get("gateway") if isinstance((cfg or {}).get("gateway"), dict) else {}
    bind = gateway.get("bind") if isinstance(gateway.get("bind"), str) else DEFAULT_BIND
    port = gateway.get("port") if isinstance(gateway.get("port"), int) else DEFAULT_PORT
    guard = guard_state(cfg, guard_id)[0] if cfg is not None else None
    watched = _same(cfg_path, watched_configs)
    out.update(
        config_path=str(cfg_path),
        configured=True,
        running=probe("127.0.0.1", port),
        bind=bind,
        bind_scope="loopback" if bind == "loopback" else "network",
        guard_plugin=guard,
        watched=watched,
    )
    if cfg is None:
        reasons.append("config unreadable")
    elif guard != "enabled":
        reasons.append(f"guard plugin {guard}")
    if not watched:
        reasons.append("no SG-Advance sensor watches this config")
    out["managed"] = not reasons
    out["unmanaged_reasons"] = reasons
    return out


def scan(
    home: Path,
    *,
    watched_configs: Iterable[Path] = (),
    path_env: str | None = None,
    probe: Probe = port_open,
    platform: str = sys.platform,
    roots: Iterable[str] = GLOBAL_ROOTS,
) -> list[dict[str, Any]]:
    code = find_code(home, path_env, roots)
    instances = find_instances(home)
    services = find_services(home, platform)
    watched = list(watched_configs)
    primary = code[0] if code else None
    rows = [describe(i, primary, services=services, watched_configs=watched, probe=probe) for i in instances]
    if not instances:  # installed but never set up: one row per copy of the code
        rows += [describe(None, c, services=services, watched_configs=watched, probe=probe) for c in code]
    return rows


class AgentDiscoveryAdapter:
    """Periodic discovery scan; emits ``install.snapshot`` per install when it appears or changes."""

    name = "agent-discovery"

    def __init__(
        self,
        *,
        home: Path | None = None,
        watched_configs: Iterable[Path] = (),
        interval: float = 600.0,
        path_env: str | None = None,
        probe: Probe = port_open,
        platform: str = sys.platform,
        roots: Iterable[str] = GLOBAL_ROOTS,
    ) -> None:
        self.home = home or Path.home()
        self.roots = tuple(roots)
        self.watched_configs = [Path(p) for p in watched_configs]
        self.interval = interval
        self.path_env = path_env
        self.probe = probe
        self.platform = platform
        self._last: dict[str, dict[str, Any]] = {}
        self.snapshots = 0

    def scan(self) -> list[dict[str, Any]]:
        return scan(
            self.home,
            watched_configs=self.watched_configs,
            path_env=self.path_env,
            probe=self.probe,
            platform=self.platform,
            roots=self.roots,
        )

    def poll(self, ctx: AdapterContext, rows: list[dict[str, Any]] | None = None) -> int:
        """Emit what changed since the last scan. Returns the number of snapshots emitted."""
        rows = self.scan() if rows is None else rows
        now = {r["instance"]: r for r in rows}
        sent = 0
        for key, row in now.items():
            before = self._last.get(key)
            if row == before:
                continue
            changed = [] if before is None else sorted(k for k in row if before.get(k) != row.get(k))
            self._emit(ctx, {**row, "changed": changed})
            sent += 1
        for key, row in self._last.items():
            if key not in now:
                self._emit(ctx, {**row, "present": False, "running": False, "changed": ["present"]})
                sent += 1
        self._last = now
        return sent

    def _emit(self, ctx: AdapterContext, payload: dict[str, Any]) -> None:
        event = AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": ctx.user_id},
                "agent": {"type": "openclaw", "session_id": f"install:{payload['instance']}"},
                "source": {"sensor": SensorType.AGENT_DISCOVERY},
                "payload": {"kind": "install.snapshot", **payload},
            }
        )
        state = "managed" if payload.get("managed") else "unmanaged"
        if not payload.get("present", True):
            state = "gone"
        log.info("openclaw install %s: %s", payload["instance"], state)
        ctx.record(ctx.evaluate(event))
        self.snapshots += 1

    async def run(self, ctx: AdapterContext) -> None:
        while True:
            try:
                rows = await asyncio.to_thread(self.scan)  # file reads and a port probe
                self.poll(ctx, rows)  # recording stays on the event loop
            except Exception:  # noqa: BLE001 - a failed scan must not stop the sensor
                log.exception("agent discovery scan failed")
            await asyncio.sleep(self.interval)

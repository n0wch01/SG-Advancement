"""OpenClaw baseline watch (M5d): read the gateway's own config file, emit ``config.snapshot``.

Why the config and not the gateway: disabling the SG-Advance plugin (``openclaw plugins disable``)
writes the config first and only takes full effect when the gateway reloads or restarts. Watching
the file reports the change before that gap opens; the plugin heartbeat (M5c) only notices after.

What leaves the endpoint is an allowlist, never the file: ``openclaw.json`` also holds the gateway
token and account e-mails. Only these are copied:

- the guard plugin's state (``plugins.enabled/allow/deny``, ``plugins.entries.<id>.enabled``)
- plugin ids, versions and enablement (``plugins.entries``, ``plugins.installs``, load paths' manifests)
- exec policy per scope (``tools.exec.security/ask/mode/host``, ``tools.elevated.enabled``)
- the runtime that runs each configured model (``agentRuntime.id`` at agent > default-agent >
  provider-model > provider precedence, and agent ``runtime.type: acp``)
- the sandbox per scope (``agents.defaults.sandbox`` / ``agents.entries.<id>.sandbox``: mode, workspaceAccess,
  scope) and ``agents.defaults.elevatedDefault``, with OpenClaw's runtime defaults filled in when unset

A snapshot goes out at start and whenever these values change (polling mtime; the file is small).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...schema import AgentEvent
from .base import AdapterContext

log = logging.getLogger(__name__)

GUARD_PLUGIN_ID = "sg-advance"
DEFAULT_CONFIG = Path("~/.openclaw/openclaw.json")
UNPINNED = "default"


def _get(doc: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc


def _model_key(ref: str) -> str:
    """``openai/gpt-6-astra@openai:setup-…`` → ``openai/gpt-6-astra`` (drop the auth profile)."""
    return ref.split("@", 1)[0].strip()


def _model_refs(spec: Any) -> list[str]:
    """``model`` is a string or ``{primary, fallbacks}``."""
    if isinstance(spec, str):
        return [_model_key(spec)]
    if isinstance(spec, dict):
        refs = [spec.get("primary"), *(spec.get("fallbacks") or [])]
        return [_model_key(r) for r in refs if isinstance(r, str)]
    return []


def _manifest_id(load_path: str) -> str | None:
    try:
        doc = json.loads((Path(load_path).expanduser() / "openclaw.plugin.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None
    pid = doc.get("id") if isinstance(doc, dict) else None
    return pid if isinstance(pid, str) else None


def guard_state(cfg: dict[str, Any], guard_id: str = GUARD_PLUGIN_ID) -> tuple[str, str]:
    plugins = _get(cfg, "plugins") or {}
    if plugins.get("enabled") is False:
        return "disabled", "plugins.enabled=false (all plugins off)"
    if guard_id in (plugins.get("deny") or []):
        return "disabled", f"plugins.deny contains {guard_id}"
    allow = plugins.get("allow")
    if allow and guard_id not in allow:
        return "disabled", f"plugins.allow does not list {guard_id}"
    entry = _get(plugins, "entries", guard_id)
    if isinstance(entry, dict) and entry.get("enabled") is False:
        return "disabled", f"plugins.entries.{guard_id}.enabled=false"
    installed = guard_id in (plugins.get("installs") or {})
    load_paths = [p for p in (_get(plugins, "load", "paths") or []) if isinstance(p, str)]
    on_path = any(_manifest_id(p) == guard_id for p in load_paths)
    if entry is None and not installed and not on_path:
        return "missing", f"{guard_id} is neither configured, installed nor on a load path"
    return "enabled", f"{guard_id} enabled"


def plugin_list(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    plugins = _get(cfg, "plugins") or {}
    out: dict[str, dict[str, Any]] = {}
    for pid, entry in (plugins.get("entries") or {}).items():
        enabled = not (isinstance(entry, dict) and entry.get("enabled") is False)
        out[pid] = {"plugin_id": pid, "enabled": enabled}
    for pid, rec in (plugins.get("installs") or {}).items():
        item = out.setdefault(pid, {"plugin_id": pid, "enabled": True})
        if isinstance(rec, dict):
            if isinstance(rec.get("version"), str):
                item["version"] = rec["version"]
            if isinstance(rec.get("source"), str):
                item["source"] = rec["source"]
    for path in _get(plugins, "load", "paths") or []:
        if isinstance(path, str) and (pid := _manifest_id(path)):
            out.setdefault(pid, {"plugin_id": pid, "enabled": True})["source"] = "path"
    return sorted(out.values(), key=lambda p: p["plugin_id"])


def _exec_policy(scope: str, tools: Any) -> dict[str, Any]:
    exec_ = _get(tools, "exec") or {}
    policy: dict[str, Any] = {"scope": scope}
    for key in ("security", "ask", "mode", "host"):
        if isinstance(exec_.get(key), str):
            policy[key] = exec_[key]
    elevated = _get(tools, "elevated", "enabled")
    if isinstance(elevated, bool):
        policy["elevated"] = elevated
    return policy


def exec_policies(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    out = [_exec_policy("global", _get(cfg, "tools"))]
    for aid, entry in sorted((_get(cfg, "agents", "entries") or {}).items()):
        tools = _get(entry, "tools")
        if isinstance(tools, dict) and ("exec" in tools or "elevated" in tools):
            out.append(_exec_policy(f"agent:{aid}", tools))
    return out


def _pin(spec: Any) -> str | None:
    rid = _get(spec, "agentRuntime", "id")
    return rid if isinstance(rid, str) and rid else None


def runtime_pins(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    providers = _get(cfg, "models", "providers") or {}

    def provider_pin(model: str) -> str | None:
        prov, _, name = model.partition("/")
        pspec = providers.get(prov) or {}
        for m in pspec.get("models") or []:
            if isinstance(m, dict) and m.get("id") in (name, model) and (p := _pin(m)):
                return p
        return _pin(pspec)

    defaults = _get(cfg, "agents", "defaults") or {}
    default_models = defaults.get("models") or {}

    def resolve(model: str, agent_models: dict[str, Any]) -> str:
        return (
            _pin(agent_models.get(model))
            or _pin(default_models.get(model))
            or provider_pin(model)
            or UNPINNED
        )

    out = []
    for model in sorted(set(_model_refs(defaults.get("model"))) | {_model_key(k) for k in default_models}):
        out.append({"scope": "defaults", "model": model, "runtime": resolve(model, {})})
    for aid, entry in sorted((_get(cfg, "agents", "entries") or {}).items()):
        if not isinstance(entry, dict):
            continue
        if _get(entry, "runtime", "type") == "acp":  # an external ACP harness runs this agent's tools
            out.append({"scope": f"agent:{aid}", "model": "*", "runtime": "acp"})
            continue
        agent_models = entry.get("models") or {}
        models = set(_model_refs(entry.get("model"))) | {_model_key(k) for k in agent_models}
        for model in sorted(models):
            out.append({"scope": f"agent:{aid}", "model": model, "runtime": resolve(model, agent_models)})
    return out


# OpenClaw 2026.11.3 runtime defaults when nothing is configured (sandbox?.mode ?? "off",
# workspaceAccess ?? "none", elevatedDefault ?? "on").
SANDBOX_DEFAULT_MODE = "off"
ELEVATED_DEFAULT = "on"


def _sandbox(scope: str, spec: Any, *, defaults: bool) -> dict[str, Any] | None:
    spec = spec if isinstance(spec, dict) else {}
    mode = spec.get("mode") if isinstance(spec.get("mode"), str) else None
    if not defaults and mode is None and not spec:
        return None  # the agent inherits the defaults row
    out: dict[str, Any] = {
        "scope": scope,
        "mode": mode or (SANDBOX_DEFAULT_MODE if defaults else None),
        "mode_source": "set" if mode else ("default" if defaults else None),
    }
    for key, field in (("workspaceAccess", "workspace_access"), ("scope", "scope_kind")):
        if isinstance(spec.get(key), str):
            out[field] = spec[key]
    return out


def sandboxes(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    defaults = _get(cfg, "agents", "defaults") or {}
    row = _sandbox("defaults", defaults.get("sandbox"), defaults=True) or {}
    elevated = defaults.get("elevatedDefault")
    row["elevated_default"] = elevated if isinstance(elevated, str) else ELEVATED_DEFAULT
    out = [row]
    for aid, entry in sorted((_get(cfg, "agents", "entries") or {}).items()):
        if isinstance(entry, dict) and (r := _sandbox(f"agent:{aid}", entry.get("sandbox"), defaults=False)):
            out.append(r)
    return out


def delegation_grants(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """``subagents.delegateToolsTo`` per agent: an operator lifting that agent's tool denials for its
    delegation targets (the child gets tools the parent may not use)."""
    out = []
    for aid, entry in sorted((_get(cfg, "agents", "entries") or {}).items()):
        to = _get(entry, "subagents", "delegateToolsTo") if isinstance(entry, dict) else None
        if isinstance(to, list) and (names := sorted({str(t) for t in to if isinstance(t, str)})):
            out.append({"agent_id": str(aid), "to": names})
    return out


def posture(cfg: dict[str, Any], guard_id: str = GUARD_PLUGIN_ID) -> dict[str, Any]:
    """The allowlisted, comparable view of the config (the payload minus kind/path/changed)."""
    state, detail = guard_state(cfg, guard_id)
    return {
        "guard_plugin": state,
        "guard_detail": detail,
        "plugins": plugin_list(cfg),
        "exec_policies": exec_policies(cfg),
        "runtimes": runtime_pins(cfg),
        "sandboxes": sandboxes(cfg),
        "delegation_grants": delegation_grants(cfg),
    }


def changed_fields(before: dict[str, Any] | None, after: dict[str, Any]) -> list[str]:
    if before is None:
        return []
    return sorted(k for k in after if before.get(k) != after.get(k))


@dataclass
class _Stamp:
    mtime_ns: int
    size: int


class OpenClawConfigAdapter:
    """Polls the OpenClaw config file and emits a ``config.snapshot`` when the posture changes."""

    name = "openclaw-config"

    def __init__(
        self, path: Path = DEFAULT_CONFIG, interval: float = 2.0, guard_id: str = GUARD_PLUGIN_ID
    ) -> None:
        self.path = path.expanduser()
        self.interval = interval
        self.guard_id = guard_id
        self._stamp: _Stamp | None = None
        self._last: dict[str, Any] | None = None
        self.snapshots = 0  # for tests and status

    def _read(self) -> dict[str, Any] | None:
        try:
            doc = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            # OpenClaw writes plain JSON; a hand edit may leave it mid-write or as JSON5. Retry later.
            log.warning("cannot parse %s: %s", self.path, e)
            return None
        return doc if isinstance(doc, dict) else None

    def poll(self, ctx: AdapterContext) -> bool:
        """One check. Returns True when a snapshot was emitted."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        stamp = _Stamp(st.st_mtime_ns, st.st_size)
        if stamp == self._stamp:
            return False
        cfg = self._read()
        if cfg is None:
            return False
        self._stamp = stamp
        now = posture(cfg, self.guard_id)
        if now == self._last:  # e.g. only the token or an unrelated setting changed
            return False
        changed = changed_fields(self._last, now)
        self._last = now
        self._emit(ctx, now, changed)
        return True

    def _emit(self, ctx: AdapterContext, now: dict[str, Any], changed: list[str]) -> None:
        event = AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": ctx.user_id},
                "agent": {"type": "openclaw", "session_id": "config:openclaw"},
                "source": {"sensor": "openclaw_config"},
                "payload": {
                    "kind": "config.snapshot",
                    "product": "openclaw",
                    "path": str(self.path),
                    "changed": changed,
                    **now,
                },
            }
        )
        if changed:
            log.info("openclaw config changed: %s", ", ".join(changed))
        ctx.record(ctx.evaluate(event))
        self.snapshots += 1

    async def run(self, ctx: AdapterContext) -> None:
        while True:
            try:
                self.poll(ctx)
            except Exception:  # noqa: BLE001 - keep watching; a bad read must not stop the sensor
                log.exception("openclaw config check failed")
            await asyncio.sleep(self.interval)

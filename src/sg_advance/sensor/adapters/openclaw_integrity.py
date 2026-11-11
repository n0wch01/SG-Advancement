"""Installed OpenClaw code vs. signed packages (M5d).

Every few minutes, and whenever the policy's manifests change, the sensor:

1. asks OpenClaw what it loaded (``openclaw plugins list --json``: id, origin, rootDir, version);
2. hashes each plugin directory and the OpenClaw core (``integrity.dir_digest``);
3. compares with the policy manifests — digests the control plane derived from npm tarballs it
   verified (registry signature + Sigstore provenance, ``server/supply.py``);
4. emits ``integrity.report`` when the result changes, and updates the ``openclaw_plugins`` trusted
   set so name-based plugin rules stop flagging verified bundled plugins;
5. quarantines tampered plugins (``openclaw plugins disable <id>``) when the rule says so.

OpenClaw's own ``origin`` field is only a hint: it is OpenClaw describing itself. What counts is
whether the bytes on disk are the bytes the publisher signed. The core is hashed too, because a
modified core could lie about everything else.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...integrity import OPENCLAW_EXTENSIONS, Manifest, dir_digest, lookup
from ...schema import AgentEvent, Enforcement, ResponseAction
from .base import AdapterContext
from .openclaw_config import GUARD_PLUGIN_ID

log = logging.getLogger(__name__)

TRUSTED_SET = "openclaw_plugins"
GOOD_TRUST = ("approved", "trusted")
Lister = Callable[[], list[dict[str, Any]]]
Disabler = Callable[[str], tuple[bool, str]]


def _cli(openclaw: str, *args: str, timeout: float = 90.0) -> subprocess.CompletedProcess[str]:
    exe = shutil.which(openclaw) or openclaw
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout, check=False)


def cli_lister(openclaw: str = "openclaw") -> Lister:
    def run() -> list[dict[str, Any]]:
        res = _cli(openclaw, "plugins", "list", "--json")
        if res.returncode != 0:
            raise RuntimeError(f"openclaw plugins list failed: {res.stderr.strip()[:200]}")
        doc = json.loads(res.stdout)
        return list(doc.get("plugins") or [])

    return run


def cli_disabler(openclaw: str = "openclaw") -> Disabler:
    def run(plugin_id: str) -> tuple[bool, str]:
        res = _cli(openclaw, "plugins", "disable", plugin_id, timeout=60.0)
        return res.returncode == 0, (res.stderr or res.stdout).strip()[:200]

    return run


def _npm_name(spec: str) -> str:
    """``@openclaw/codex`` / ``@openclaw/codex@1.2`` / ``foo@1`` → package name."""
    head, sep, _ = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
    return ("@" + head) if spec.startswith("@") else head


def _version_manifest(manifests: list[Manifest], package: str, version: str | None) -> Manifest | None:
    for m in manifests:
        if m.package == package and m.version == version:
            return m
    return None


def _check(component: str, digest: str, man: Manifest | None, manifests: list[Manifest]) -> tuple[str, str]:
    """(integrity, trust) for one component."""
    if man is not None:
        if man.status == "rejected":  # the version failed verification: nothing to compare with
            return "pending", "rejected"
        expected = man.components.get(component)
        if expected is None:  # e.g. a folder dropped into dist/extensions that the package never had
            return "mismatch", man.status
        return ("verified" if expected == digest else "mismatch"), man.status
    pinned = lookup(manifests, component, digest)  # local pins (in-house plugins) or other versions
    if pinned is not None:
        return "verified", pinned.status
    return "pending", "unverified"


def core_root(plugins: list[dict[str, Any]]) -> Path | None:
    """The OpenClaw package directory: bundled plugins live in <root>/dist/extensions/<id>."""
    for p in plugins:
        if p.get("origin") == "bundled" and p.get("rootDir"):
            ext = Path(p["rootDir"]).parent
            if ext.as_posix().endswith(OPENCLAW_EXTENSIONS):
                return ext.parents[1]
    return None


def build_report(
    plugins: list[dict[str, Any]], manifests: list[Manifest], digest: Callable[..., str] = dir_digest
) -> dict[str, Any]:
    root = core_root(plugins)
    version = None
    core = None
    if root is not None:
        try:
            version = json.loads((root / "package.json").read_text("utf-8")).get("version")
        except (OSError, ValueError):
            version = None
        d = digest(root, exclude=(OPENCLAW_EXTENSIONS,))
        integrity, trust = _check("core", d, _version_manifest(manifests, "openclaw", version), manifests)
        core = {
            "component": "core",
            "package": "openclaw",
            "version": version,
            "origin": "core",
            "path": str(root),
            "digest": d,
            "integrity": integrity,
            "trust": trust,
        }

    out = []
    for p in sorted(plugins, key=lambda p: p.get("id", "")):
        pid, path = p.get("id"), p.get("rootDir")
        if not pid or not path or p.get("status") not in (None, "loaded"):
            continue  # disabled or failed plugins run no code
        component = f"plugin:{pid}"
        d = digest(Path(path))
        origin = p.get("origin")
        spec = (p.get("trust") or {}).get("installSpec")
        if origin == "bundled":
            package, pver = "openclaw", version
        elif spec and (p.get("trust") or {}).get("installSource") == "npm":
            package, pver = _npm_name(spec), p.get("version")
        else:  # local path / workspace: only a pin can vouch for it
            package, pver = None, p.get("version")
        man = _version_manifest(manifests, package, pver) if package else None
        integrity, trust = _check(component, d, man, manifests)
        if package is None and integrity == "pending":
            integrity = "unknown"
        out.append(
            {
                "component": component,
                "package": package,
                "version": pver,
                "origin": origin,
                "path": path,
                "digest": d,
                "integrity": integrity,
                "trust": trust,
                "enabled": bool(p.get("enabled", True)),
            }
        )
    return {
        "kind": "integrity.report",
        "product": "openclaw",
        "version": version,
        "core": core,
        "plugins": out,
    }


class OpenClawIntegrityAdapter:
    name = "openclaw-integrity"

    def __init__(
        self,
        interval: float = 300.0,
        policy_check: float = 30.0,
        lister: Lister | None = None,
        disabler: Disabler | None = None,
        quarantine: bool = True,
        guard_id: str = GUARD_PLUGIN_ID,
    ) -> None:
        self.interval = interval
        self.policy_check = policy_check
        self.lister = lister or cli_lister()
        self.disabler = disabler or cli_disabler()
        self.quarantine = quarantine
        self.guard_id = guard_id
        self._last: dict[str, Any] | None = None
        self.reports = 0

    def _manifests(self, ctx: AdapterContext) -> list[Manifest]:
        policy = ctx.sensor.policy
        return [Manifest.model_validate(m) for m in (policy.manifests if policy else ())]

    def scan(self, ctx: AdapterContext) -> bool:
        """One pass. Returns True when a report was emitted."""
        payload = build_report(self.lister(), self._manifests(ctx))
        trusted = {
            c["component"].removeprefix("plugin:")
            for c in payload["plugins"]
            if c["integrity"] == "verified" and c["trust"] in GOOD_TRUST
        }
        ctx.sensor.set_trusted(TRUSTED_SET, trusted)
        if payload == self._last:
            return False
        self._last = payload
        event = AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": ctx.user_id},
                "agent": {"type": "openclaw", "session_id": "integrity:openclaw"},
                "source": {"sensor": "openclaw_integrity"},
                "payload": payload,
            }
        )
        result = ctx.evaluate(event)
        ctx.record(result, self._enforce(result.verdict.action, payload))
        self.reports += 1
        bad = [c["component"] for c in payload["plugins"] if c["integrity"] == "mismatch"]
        if bad:
            log.warning("openclaw plugins do not match their signed packages: %s", ", ".join(bad))
        return True

    def _enforce(self, action: ResponseAction, payload: dict[str, Any]) -> Enforcement | None:
        if action is not ResponseAction.QUARANTINE:
            return None
        targets = [
            c["component"].removeprefix("plugin:") for c in payload["plugins"] if c["integrity"] == "mismatch"
        ]
        if not targets:
            return None
        if not self.quarantine:
            return Enforcement(
                action=action, enforced=False, enforcer="openclaw_integrity", detail="quarantine off"
            )
        done, notes = [], []
        for pid in targets:
            if pid == self.guard_id:  # disabling our own guard would only remove the control
                notes.append(f"{pid}: not disabled (it is the SG-Advance guard)")
                continue
            ok, msg = self.disabler(pid)
            (done if ok else notes).append(pid if ok else f"{pid}: {msg}")
            log.warning("quarantine %s: %s", pid, "disabled" if ok else msg)
        detail = "openclaw plugins disable " + ", ".join(done) if done else "nothing disabled"
        if notes:
            detail += "; " + "; ".join(notes)
        return Enforcement(
            action=action, enforced=bool(done) and not notes, enforcer="openclaw_integrity", detail=detail
        )

    async def run(self, ctx: AdapterContext) -> None:
        seen_policy: str | None = None
        next_scan = 0.0
        loop = asyncio.get_running_loop()
        while True:
            version = ctx.sensor.policy.version if ctx.sensor.policy else None
            if loop.time() >= next_scan or version != seen_policy:
                seen_policy = version
                try:
                    await asyncio.to_thread(self.scan, ctx)
                except Exception:  # noqa: BLE001 - keep checking; one failed pass must not stop the sensor
                    log.exception("openclaw integrity scan failed")
                next_scan = loop.time() + self.interval
            await asyncio.sleep(self.policy_check)

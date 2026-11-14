"""Remote response on the endpoint (M11): run the actions security queued for this device.

The daemon polls ``GET /v1/actions`` on its flush tick. Blocking a conversation or a person only
changes a sensor-maintained set (``remote_blocked_sessions`` / ``remote_blocked_users``); the rules
in ``rules/remote_response.yaml`` read it, so the gateway plugin blocks every further tool call before
it runs. The sets are persisted with the other sensor sets, so a restart keeps the block.
Adapters add what only they can do (``abort_session``, ``disable_plugin``, ``disable_skill``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from .adapters.base import AdapterContext
from .client import ControlPlaneError, Offline
from .state import write_private

log = logging.getLogger(__name__)

BLOCKED_SESSIONS = "remote_blocked_sessions"
BLOCKED_USERS = "remote_blocked_users"
ELEVATED_RISK_USERS = "elevated_risk_users"


async def refresh_risk(ctx: AdapterContext) -> bool:
    """Zero trust (2026-11-13): who among this device's people is elevated risk now. Kept on failure:
    being cut off must not lower anyone's risk."""
    try:
        doc = await asyncio.to_thread(ctx.sensor.client.get_risk)
    except (Offline, ControlPlaneError) as e:
        log.debug("risk unavailable: %s", e)
        return False
    users = {str(u) for u in doc.get("elevated_users", [])}
    if users != ctx.sensor.trusted.get(ELEVATED_RISK_USERS, set()):
        log.warning("elevated risk users on this device: %s", ", ".join(sorted(users)) or "none")
    ctx.sensor.set_trusted(ELEVATED_RISK_USERS, users)
    return True


def install_core_handlers(ctx: AdapterContext) -> None:
    sensor = ctx.sensor

    def setter(name: str, add: bool, what: str):
        async def handle(target: str) -> tuple[bool, str]:
            current = set(sensor.trusted.get(name, set()))
            changed = (target not in current) if add else (target in current)
            sensor.set_trusted(name, current | {target} if add else current - {target})
            verb = "blocked" if add else "unblocked"
            return True, f"{what} {verb}" + ("" if changed else " (no change)")

        return handle

    ctx.actions.setdefault("block_session", setter(BLOCKED_SESSIONS, True, "conversation"))
    ctx.actions.setdefault("unblock_session", setter(BLOCKED_SESSIONS, False, "conversation"))
    ctx.actions.setdefault("block_user", setter(BLOCKED_USERS, True, "person"))
    ctx.actions.setdefault("unblock_user", setter(BLOCKED_USERS, False, "person"))


DONE_FILE = "remote-actions.json"
DONE_KEEP = 500


def _done_path(ctx: AdapterContext) -> Path:
    return ctx.sensor.home.root / DONE_FILE


def _load_done(ctx: AdapterContext) -> dict[str, dict[str, Any]]:
    try:
        doc = json.loads(_done_path(ctx).read_text("utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_done(ctx: AdapterContext, done: dict[str, dict[str, Any]]) -> None:
    keep = dict(list(done.items())[-DONE_KEEP:])
    write_private(_done_path(ctx), json.dumps(keep))


def applied_of(supported: bool, ok: bool, detail: str) -> str:
    """What the device actually did, apart from what was asked (CLAUDE.md, 2026-11-13)."""
    if not supported:
        return "not_supported"
    if not ok:
        return "failed"
    return "already_applied" if "(no change)" in detail else "applied"


async def run_pending(ctx: AdapterContext) -> int:
    """Fetch, run and report this device's pending actions. Returns how many ran.

    Each action id runs once: the result is kept on disk before it is reported, so an action handed
    out again (its result report was lost, or the sensor restarted in between) is reported, not rerun."""
    client = ctx.sensor.client
    try:
        actions = await asyncio.to_thread(client.get_actions)
    except (Offline, ControlPlaneError) as e:
        log.debug("remote actions unavailable: %s", e)
        return 0
    done = _load_done(ctx)
    ran = 0
    for a in actions:
        record = done.get(a["id"])
        if record is None:
            handler = ctx.actions.get(a["action"])
            if handler is None:
                ok, detail = False, f"{a['action']} is not supported on this device"
            else:
                try:
                    ok, detail = await handler(a["target"])
                except Exception as e:  # noqa: BLE001 - report the failure instead of losing the action
                    ok, detail = False, f"error: {e}"
            record = {"ok": ok, "detail": detail, "applied": applied_of(handler is not None, ok, detail)}
            done[a["id"]] = record
            _save_done(ctx, done)
            ran += 1
            log.warning("remote action %s %s: %s (%s)", a["action"], a["target"], record["applied"], detail)
        else:
            log.info("remote action %s handed out again (attempt %s): reporting, not rerunning",
                     a["id"], a.get("attempt"))  # fmt: skip
        try:
            await asyncio.to_thread(
                client.report_action, a["id"], record["ok"], record["detail"], record["applied"]
            )
        except (Offline, ControlPlaneError) as e:
            log.warning("could not report remote action %s (it will be handed out again): %s", a["id"], e)
    return ran

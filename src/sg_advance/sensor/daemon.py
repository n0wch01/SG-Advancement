"""Local sensor daemon (``sga-sensor run``).

One long-running process per endpoint. It owns the rule engine, so stateful rules (sequence,
rate, repeat) see every event from every adapter on this machine:

- runs the configured adapters (OpenClaw gateway watcher, replay, ...);
- re-syncs the signed policy every ``sync_interval`` seconds;
- flushes the spool every ``flush_interval`` seconds, and once more on shutdown.

Network calls run in worker threads so a slow control plane never stalls event handling.
M5c adds a local socket here so the OpenClaw plugin (and later Claude Code hooks, M6) can ask the
daemon for verdicts before a tool runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from .adapters.base import Adapter, AdapterContext
from .core import NoPolicy, Sensor, SyncStatus
from .plugin_api import LocalApiServer, record_health
from .spool import FlushResult

log = logging.getLogger(__name__)


@dataclass
class DaemonStats:
    policy_syncs: int = 0
    flushes: int = 0
    last_flush: FlushResult | None = None
    last_sync: SyncStatus | None = None
    flush_errors: int = 0
    last_flush_error: str | None = None
    adapter_errors: dict[str, str] = field(default_factory=dict)
    remote_actions: int = 0


class Daemon:
    def __init__(
        self,
        sensor: Sensor,
        adapters: Sequence[Adapter],
        ctx: AdapterContext,
        *,
        sync_interval: float = 60.0,
        flush_interval: float = 5.0,
        local_api: LocalApiServer | None = None,
        health_interval: float = 10.0,  # cheap; bounds how late a lost plugin is reported
    ) -> None:
        self.sensor = sensor
        self.adapters = list(adapters)
        self.ctx = ctx
        from .response import install_core_handlers

        install_core_handlers(ctx)  # remote block/unblock (M11); adapters add their own on run
        self.sync_interval = sync_interval
        self.flush_interval = flush_interval
        self.local_api = local_api
        self.health_interval = health_interval
        self.stats = DaemonStats()
        self.ready = asyncio.Event()  # set once a policy is loaded and adapters are running

    async def _wait_for_policy(self) -> None:
        """No policy means no verdicts. Keep trying instead of exiting: the control plane may
        simply not be up yet (first boot, container start order)."""
        while True:
            try:
                self.stats.last_sync = await asyncio.to_thread(self.sensor.start)
                return
            except NoPolicy as e:
                log.warning("%s; retrying in %.0fs", e, self.sync_interval)
                await asyncio.sleep(self.sync_interval)

    async def _sync_loop(self) -> None:
        while True:
            await asyncio.sleep(self.sync_interval)
            try:
                self.stats.last_sync = await asyncio.to_thread(self.sensor.sync_policy)
                self.stats.policy_syncs += 1
            except Exception as e:  # noqa: BLE001 - keep the last good policy
                log.warning("policy sync failed, keeping current policy: %s", e)

    def check_plugin_health(self, now: float | None = None) -> str | None:
        """Emit a sensor.health event when the gateway plugin's heartbeats stop."""
        plugins = self.ctx.plugins
        said_bye = plugins.bye_at is not None
        if plugins.check(now) != "lost":
            return None
        last = plugins.last_contact
        quiet = (now or time.time()) - last if last is not None else None
        if said_bye:
            detail = f"plugin was unloaded by the gateway and did not return within {plugins.bye_grace:.0f}s"
        elif quiet is not None:
            detail = f"no heartbeat for {quiet:.0f}s"
        else:
            detail = "no heartbeat since the sensor started"
        log.warning("openclaw plugin heartbeat lost (%s)", detail)
        record_health(self.ctx, "lost", detail, last)
        return "lost"

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(self.health_interval)
            try:
                self.check_plugin_health()
            except Exception:  # never let monitoring take the daemon down
                log.exception("plugin health check failed")

    async def flush_once(self) -> FlushResult:
        r = await asyncio.to_thread(self.sensor.flush)
        self.stats.flushes += 1
        self.stats.last_flush = r
        if r.error:
            log.info("flush stopped: %s (%d pending)", r.error, r.remaining)
        return r

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            try:
                await self.flush_once()
            except Exception as e:  # noqa: BLE001 - a bad flush must not take the sensor down
                # Offline/auth are handled inside the spool; anything else (a corrupt row, an
                # unexpected HTTP library error) is logged and retried on the next tick. Before this,
                # one such error ended run() and with it the plugin socket and every adapter.
                self.stats.flush_errors += 1
                self.stats.last_flush_error = repr(e)
                log.exception("flush failed; retrying in %.1fs", self.flush_interval)

    async def _actions_loop(self) -> None:
        """Remote response (M11): polled on the flush tick, so a block lands within seconds."""
        from .response import run_pending

        while True:
            await asyncio.sleep(self.flush_interval)
            try:
                self.stats.remote_actions += await run_pending(self.ctx)
            except Exception:  # noqa: BLE001 - never let remote response take the daemon down
                log.exception("remote actions failed")

    async def _run_adapter(self, adapter: Adapter) -> None:
        try:
            await adapter.run(self.ctx)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # an adapter bug must not take the whole sensor down
            log.exception("adapter %s crashed", adapter.name)
            self.stats.adapter_errors[adapter.name] = repr(e)

    async def run(self) -> None:
        await self._wait_for_policy()
        if self.local_api is not None:
            await self.local_api.start()
        tasks = [
            asyncio.create_task(self._sync_loop()),
            asyncio.create_task(self._flush_loop()),
            asyncio.create_task(self._health_loop()),
            asyncio.create_task(self._actions_loop()),
        ]
        tasks += [asyncio.create_task(self._run_adapter(a), name=f"adapter:{a.name}") for a in self.adapters]
        self.ready.set()
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
            if self.local_api is not None:
                with contextlib.suppress(Exception):
                    await self.local_api.close()
            with contextlib.suppress(Exception):
                await self.flush_once()  # best effort: ship what we have before exiting

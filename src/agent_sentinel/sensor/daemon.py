"""Local sensor daemon (``sentinel-sensor run``).

One long-running process per endpoint. It owns the rule engine, so stateful rules (sequence,
rate, repeat) see every event from every adapter on this machine:

- runs the configured adapters (OpenClaw gateway watcher, replay, ...);
- re-syncs the signed policy every ``sync_interval`` seconds;
- flushes the spool every ``flush_interval`` seconds, and once more on shutdown.

Network calls run in worker threads so a slow control plane never stalls event handling.
M6 adds a local socket here so short-lived hook processes can ask the daemon for verdicts.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from .adapters.base import Adapter, AdapterContext
from .core import NoPolicy, Sensor, SyncStatus
from .spool import FlushResult

log = logging.getLogger(__name__)


@dataclass
class DaemonStats:
    policy_syncs: int = 0
    flushes: int = 0
    last_flush: FlushResult | None = None
    last_sync: SyncStatus | None = None
    adapter_errors: dict[str, str] = field(default_factory=dict)


class Daemon:
    def __init__(
        self,
        sensor: Sensor,
        adapters: Sequence[Adapter],
        ctx: AdapterContext,
        *,
        sync_interval: float = 60.0,
        flush_interval: float = 5.0,
    ) -> None:
        self.sensor = sensor
        self.adapters = list(adapters)
        self.ctx = ctx
        self.sync_interval = sync_interval
        self.flush_interval = flush_interval
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
            await self.flush_once()

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
        tasks = [asyncio.create_task(self._sync_loop()), asyncio.create_task(self._flush_loop())]
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
            with contextlib.suppress(Exception):
                await self.flush_once()  # best effort: ship what we have before exiting

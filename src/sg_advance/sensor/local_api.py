"""The daemon's local verdict API, shared by every enforcement point on the PC (2026-11-18).

Hooks and gateway plugins on this PC ask the daemon here before a tool runs: one JSON object per line,
one response line per request. Unix socket ``SGA_HOME/sga.sock`` (0600) on macOS/Linux; on Windows
loopback TCP on a random port, with ``SGA_HOME/sga-api.json`` ``{"host", "port", "token"}`` in the user's
profile and ``"auth": token`` required on every request.

``{"op": "event", "event": <AgentEvent>}`` (Claude Code and Codex hooks) → ``decision.judge_event``.
Other ops belong to an integration and are registered by it (OpenClaw plugin: ``plugin_api.OPENCLAW_OPS``,
protocol documented there). Unknown ops are refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .adapters.base import AdapterContext
from .decision import judge_event

log = logging.getLogger(__name__)

SOCKET_NAME = "sga.sock"
ENDPOINT_FILE = "sga-api.json"
OpHandler = Callable[[AdapterContext, dict[str, Any]], dict[str, Any]]


def event_op(ctx: AdapterContext, req: dict[str, Any]) -> dict[str, Any]:
    """A full AgentEvent built by a hook (Claude Code, Codex). Errors go back to the hook, which then
    judges on its own (cached signed policy, else fail closed)."""
    if not isinstance(req.get("event"), dict):
        return {"ok": False, "error": "event must be an object"}
    try:
        return judge_event(ctx, req["event"])
    except Exception as e:  # validation errors included
        log.exception("hook event failed")
        return {"ok": False, "error": str(e)[:500]}


class LocalApiServer:
    """``path``: a unix socket (macOS, Linux). ``tcp=True``: loopback TCP + token, the endpoint
    written to ``path`` instead (Windows)."""

    def __init__(
        self,
        ctx: AdapterContext,
        path: Path,
        *,
        tcp: bool = False,
        ops: Mapping[str, OpHandler] | None = None,
    ) -> None:
        self.ctx = ctx
        self.path = path
        self.tcp = tcp
        # "event" is the agent-neutral op (a full AgentEvent from a hook). Integrations add their own
        # protocol ops (OpenClaw: plugin_api.OPENCLAW_OPS); an op touches only its own integration's state.
        self.ops: dict[str, OpHandler] = {"event": event_op, **(ops or {})}
        self.token: str | None = None
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        from .state import private_dir

        private_dir(self.path.parent)
        if self.tcp:
            import secrets

            from .state import write_private

            self.token = secrets.token_urlsafe(32)
            self._server = await asyncio.start_server(self._client, host="127.0.0.1", port=0)
            port = self._server.sockets[0].getsockname()[1]
            endpoint = {"host": "127.0.0.1", "port": port, "token": self.token, "pid": os.getpid()}
            write_private(self.path, json.dumps(endpoint))
            log.info("local verdict API listening on 127.0.0.1:%d (endpoint %s)", port, self.path)
            return
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()  # stale socket from a previous run
        old = os.umask(0o177)  # socket created 0600: only this user's processes may ask
        try:
            self._server = await asyncio.start_unix_server(self._client, path=str(self.path))
        finally:
            os.umask(old)
        log.info("local verdict API listening on %s", self.path)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                writer.write((json.dumps(await self.handle_async(line, reader)) + "\n").encode())
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _authorized(self, req: object) -> bool:
        if self.token is None:  # unix socket: the 0600 file is the access control
            return True
        import hmac

        given = req.get("auth") if isinstance(req, dict) else None
        return isinstance(given, str) and hmac.compare_digest(given, self.token)

    async def handle_async(self, line: bytes, reader: asyncio.StreamReader | None = None) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            req = None
        if self.token is not None and not self._authorized(req):
            return {"ok": False, "error": "unauthorized"}
        return self.handle(line)

    def handle(self, line: bytes) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "error": "invalid json"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "expected an object"}
        op = req.get("op")
        handler = self.ops.get(op) if isinstance(op, str) else None
        if handler is None:
            return {"ok": False, "error": f"unknown op {op!r}"}
        return handler(self.ctx, req)

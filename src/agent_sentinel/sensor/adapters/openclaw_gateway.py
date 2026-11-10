"""OpenClaw gateway WebSocket client (protocol v3), ported from SG ``scripts/openclaw_ws.py``.

Frames are JSON objects: ``{"type": "req"|"res"|"event", ...}``. Handshake:

1. server sends event ``connect.challenge`` with a nonce;
2. client sends req ``connect`` with the gateway token (and, if available, a device block signed
   with the OpenClaw CLI identity so the gateway keeps the requested scopes);
3. server answers res ``{"ok": true, "payload": {"type": "hello-ok"}}``.

Scopes used here: ``operator.read`` (subscribe, catalog), ``operator.write`` (``sessions.abort``).
Behaviour was checked against the OpenClaw 2026.4.15 gateway build (``dist/server.impl-*.js``).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

EventHandler = Callable[[dict[str, Any]], Awaitable[None]]
log = logging.getLogger(__name__)

DEFAULT_URL = "ws://127.0.0.1:18789"
CLIENT_ID = "gateway-client"  # must be one of the gateway's client id enums
CLIENT_MODE = "backend"


class GatewayError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _normalize_metadata(value: str | None) -> str:
    """Mirror OpenClaw ``normalizeDeviceMetadataForAuth`` (ASCII A-Z lowered only)."""
    s = (value or "").strip()
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


@dataclass(frozen=True)
class DeviceIdentity:
    """The OpenClaw CLI's own ``identity/device.json`` (version 1)."""

    device_id: str
    public_key_pem: str
    private_key_pem: str

    @classmethod
    def load(cls, path: Path) -> DeviceIdentity | None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict) or raw.get("version") != 1:
            return None
        did, pub, prv = raw.get("deviceId"), raw.get("publicKeyPem"), raw.get("privateKeyPem")
        if not all(isinstance(v, str) and v.strip() for v in (did, pub, prv)):
            return None
        return cls(did.strip(), pub, prv)  # type: ignore[union-attr]

    @staticmethod
    def find(explicit: str | None = None) -> Path | None:
        candidates = [explicit, os.environ.get("OPENCLAW_DEVICE_IDENTITY_PATH")]
        if state := os.environ.get("OPENCLAW_STATE_DIR"):
            candidates.append(str(Path(state) / "identity" / "device.json"))
        candidates += [
            str(Path.home() / ".openclaw" / "identity" / "device.json"),
            str(Path.home() / ".clawdbot" / "identity" / "device.json"),
        ]
        for c in candidates:
            if c and Path(c).expanduser().is_file():
                return Path(c).expanduser()
        return None

    def connect_block(self, *, token: str, nonce: str, role: str, scopes: list[str], platform: str) -> dict:
        signed_at = int(time.time() * 1000)
        payload = "|".join(
            [
                "v3",
                self.device_id,
                CLIENT_ID,
                CLIENT_MODE,
                role,
                ",".join(scopes),
                str(signed_at),
                token or "",
                nonce,
                _normalize_metadata(platform),
                "",  # device family
            ]
        )
        key = serialization.load_pem_private_key(self.private_key_pem.encode(), password=None)
        pub = serialization.load_pem_public_key(self.public_key_pem.encode())
        if not isinstance(key, Ed25519PrivateKey) or not isinstance(pub, Ed25519PublicKey):
            raise GatewayError("OpenClaw device identity must be Ed25519")
        raw_pub = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {
            "id": self.device_id,
            "publicKey": _b64url(raw_pub),
            "signature": _b64url(key.sign(payload.encode())),
            "signedAt": signed_at,
            "nonce": nonce,
        }


class GatewayConnection:
    def __init__(self, ws: Any) -> None:
        self.ws = ws
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._handlers: list[EventHandler] = []
        self._reader: asyncio.Task[None] | None = None
        # Events are handled by a separate task, in order. Handlers may send requests (e.g.
        # sessions.abort) and await the response, which only the reader can deliver; running
        # handlers inside the reader would deadlock.
        self._events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._dispatcher: asyncio.Task[None] | None = None
        self.closed = asyncio.Event()

    @classmethod
    async def open(
        cls,
        url: str,
        token: str,
        *,
        scopes: list[str],
        identity: DeviceIdentity | None = None,
        open_timeout: float = 15.0,
    ) -> GatewayConnection:
        from websockets.asyncio.client import connect  # optional dependency (extra "openclaw")

        use_proxy = os.environ.get("OPENCLAW_GATEWAY_WS_USE_SYSTEM_PROXY", "").lower() in ("1", "true", "yes")
        # Default: no system proxy, so loopback stays loopback (the gateway skips pairing for it).
        ws = await connect(url, max_size=None, open_timeout=open_timeout, proxy=True if use_proxy else None)
        try:
            nonce = await cls._await_challenge(ws, open_timeout)
            self = cls(ws)
            self._reader = asyncio.create_task(self._read_loop())
            self._dispatcher = asyncio.create_task(self._dispatch_loop())
            platform = sys.platform
            params: dict[str, Any] = {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": CLIENT_ID,
                    "version": "agent-sentinel",
                    "platform": platform,
                    "mode": CLIENT_MODE,
                },
                "role": "operator",
                "scopes": scopes,
                "caps": [],
                "commands": [],
                "permissions": {},
                "auth": {"token": token},
                "locale": "en-US",
                "userAgent": "agent-sentinel",
            }
            if identity is not None:
                params["device"] = identity.connect_block(
                    token=token, nonce=nonce, role="operator", scopes=scopes, platform=platform
                )
            res = await self.request("connect", params, timeout=30.0)
        except BaseException:
            await ws.close()
            raise
        if not res.get("ok"):
            await self.close()
            raise GatewayError(f"connect failed: {res.get('error')}")
        if (res.get("payload") or {}).get("type") != "hello-ok":
            await self.close()
            raise GatewayError(f"unexpected connect payload: {res.get('payload')!r}")
        return self

    @staticmethod
    async def _await_challenge(ws: Any, timeout: float) -> str:
        async def wait() -> str:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
                if (
                    isinstance(msg, dict)
                    and msg.get("type") == "event"
                    and msg.get("event") == "connect.challenge"
                ):
                    nonce = (msg.get("payload") or {}).get("nonce")
                    if isinstance(nonce, str) and nonce:
                        return nonce
            raise GatewayError("gateway closed before connect.challenge")

        try:
            return await asyncio.wait_for(wait(), timeout)
        except TimeoutError as e:
            raise GatewayError("timed out waiting for connect.challenge") from e

    def on_event(self, handler: EventHandler) -> None:
        self._handlers.append(handler)

    async def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> dict:
        rid = str(uuid.uuid4())
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await self.ws.send(
                json.dumps({"type": "req", "id": rid, "method": method, "params": params or {}})
            )
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(rid, None)

    async def _read_loop(self) -> None:
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") == "res":
                    fut = self._pending.pop(str(msg.get("id")), None)
                    if fut is not None and not fut.done():
                        fut.set_result(msg)
                elif msg.get("type") == "event":
                    self._events.put_nowait(msg)
        finally:
            err = ConnectionError("gateway connection closed")
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(err)
            self._pending.clear()
            self.closed.set()

    async def _dispatch_loop(self) -> None:
        while True:
            msg = await self._events.get()
            for h in list(self._handlers):
                try:
                    await h(msg)
                except Exception:  # one bad frame must not stop event handling
                    log.exception("gateway event handler failed for %s", msg.get("event"))

    async def close(self) -> None:
        if self._dispatcher is not None:
            self._dispatcher.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._dispatcher
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # closing anyway
                await self._reader
        await self.ws.close()
        self.closed.set()

"""OpenClaw gateway WebSocket client (wire protocol v3 and v4).

Originally ported from SG ``scripts/openclaw_ws.py`` (v3, 2026.4.15); extended for v4 (2026.11.3).
Frames are JSON objects ``{"type": "req"|"res"|"event", ...}``. Handshake:

1. server sends event ``connect.challenge`` ``{nonce, ts}``;
2. client sends req ``connect``: protocol range, client info, role/scopes, ``caps``, ``auth`` and a
   ``device`` block signed with the client's own Ed25519 key (``signedAt`` = challenge ``ts``);
3. server answers ``hello-ok``. After the device was approved once, ``hello-ok.auth.deviceToken`` is
   the credential for later connections.

Identity: the sensor has its **own** device identity (``SGA_HOME/openclaw-device.json``, 0600),
paired like any third-party client (``openclaw devices approve <requestId>``). It never borrows the
OpenClaw CLI's key: least privilege, visible in ``openclaw devices list``, revocable on its own.

v4 differences that matter (docs/gateway/clients.md): live tool events reach only connections that
advertise the ``tool-events`` capability — without it nothing arrives and nothing errors.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

EventHandler = Callable[[dict[str, Any]], Awaitable[None]]
log = logging.getLogger(__name__)

DEFAULT_URL = "ws://127.0.0.1:18789"
CLIENT_ID = "gateway-client"  # must be one of the gateway's client id enums
CLIENT_MODE = "backend"
MIN_PROTOCOL, MAX_PROTOCOL = 3, 4
# Only capabilities this client really implements (the gateway may change behaviour for them).
CAPS = ["tool-events", "exec-approvals"]


class GatewayError(RuntimeError):
    pass


class PairingRequired(GatewayError):
    """The gateway knows the device key but an operator has not approved it (yet)."""

    def __init__(self, request_id: str | None, detail: Any) -> None:
        hint = f"openclaw devices approve {request_id}" if request_id else "openclaw devices list / approve"
        super().__init__(f"pairing required — on the gateway host run: {hint}")
        self.request_id = request_id
        self.detail = detail


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _normalize_metadata(value: str | None) -> str:
    """Mirror OpenClaw ``normalizeDeviceMetadataForAuth`` (ASCII A-Z lowered only)."""
    s = (value or "").strip()
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _raw_public_key(public_key_pem: str) -> bytes:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(pub, Ed25519PublicKey):
        raise GatewayError("OpenClaw device identity must be Ed25519")
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class DeviceIdentity:
    """Ed25519 device identity in OpenClaw's ``device.json`` (version 1) shape, plus the device
    token the gateway issued after pairing. The gateway requires ``device_id`` to equal the hex
    sha256 of the raw public key."""

    device_id: str
    public_key_pem: str
    private_key_pem: str
    device_token: str | None = None
    token_scopes: tuple[str, ...] = field(default=())

    @classmethod
    def generate(cls) -> DeviceIdentity:
        key = Ed25519PrivateKey.generate()
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        prv_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return cls(
            hashlib.sha256(_raw_public_key(pub_pem.decode())).hexdigest(), pub_pem.decode(), prv_pem.decode()
        )

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
        token = raw.get("deviceToken") if isinstance(raw.get("deviceToken"), str) else None
        scopes = tuple(s for s in raw.get("tokenScopes") or [] if isinstance(s, str))
        return cls(did.strip(), pub, prv, token, scopes)  # type: ignore[union-attr]

    @classmethod
    def load_or_create(cls, path: Path) -> DeviceIdentity:
        ident = cls.load(path)
        if ident is None:
            ident = cls.generate()
            ident.save(path)
            log.info("created OpenClaw device identity %s… at %s", ident.device_id[:12], path)
        return ident

    def save(self, path: Path) -> None:
        from ..state import write_private  # 0600, atomic

        doc: dict[str, Any] = {
            "version": 1,
            "deviceId": self.device_id,
            "publicKeyPem": self.public_key_pem,
            "privateKeyPem": self.private_key_pem,
        }
        if self.device_token:
            doc |= {"deviceToken": self.device_token, "tokenScopes": list(self.token_scopes)}
        write_private(path, json.dumps(doc, indent=2))

    def with_token(self, token: str, scopes: list[str]) -> DeviceIdentity:
        return replace(self, device_token=token, token_scopes=tuple(scopes))

    def connect_block(
        self,
        *,
        token: str,
        nonce: str,
        role: str,
        scopes: list[str],
        platform: str,
        signed_at: int | None = None,
    ) -> dict:
        signed_at = signed_at if signed_at is not None else int(time.time() * 1000)
        payload = "|".join(
            [
                "v3",  # device-auth payload format (still v3 on wire protocol v4)
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
        if not isinstance(key, Ed25519PrivateKey):
            raise GatewayError("OpenClaw device identity must be Ed25519")
        return {
            "id": self.device_id,
            "publicKey": _b64url(_raw_public_key(self.public_key_pem)),
            "signature": _b64url(key.sign(payload.encode())),
            "signedAt": signed_at,
            "nonce": nonce,
        }


@dataclass
class Challenge:
    nonce: str
    ts: int | None  # ms; v4 requires it as the device proof's signedAt


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
        self.hello: dict[str, Any] = {}
        self.issued_device_token: tuple[str, list[str]] | None = None

    @classmethod
    async def open(
        cls,
        url: str,
        token: str | None,
        *,
        scopes: list[str],
        identity: DeviceIdentity | None = None,
        open_timeout: float = 15.0,
        password: str | None = None,
    ) -> GatewayConnection:
        """``token`` is the gateway's shared bootstrap token. When it is empty and the identity holds
        a device token from an earlier pairing, that device token is used instead (with the scopes
        it was issued for, as the reference client does)."""
        from websockets.asyncio.client import connect  # optional dependency (extra "openclaw")

        use_proxy = os.environ.get("OPENCLAW_GATEWAY_WS_USE_SYSTEM_PROXY", "").lower() in ("1", "true", "yes")
        # Default: no system proxy, so loopback stays loopback.
        ws = await connect(url, max_size=None, open_timeout=open_timeout, proxy=True if use_proxy else None)
        try:
            challenge = await cls._await_challenge(ws, open_timeout)
            self = cls(ws)
            self._reader = asyncio.create_task(self._read_loop())
            self._dispatcher = asyncio.create_task(self._dispatch_loop())
            params = cls._connect_params(token, scopes, identity, challenge, password=password)
            res = await self.request("connect", params, timeout=30.0)
        except BaseException:
            await ws.close()
            raise
        if not res.get("ok"):
            await self.close()
            err = res.get("error") or {}
            details = err.get("details") if isinstance(err, dict) else None
            if isinstance(details, dict) and details.get("code") == "PAIRING_REQUIRED":
                raise PairingRequired(details.get("requestId"), details)
            raise GatewayError(f"connect failed: {err}")
        hello = res.get("payload") or {}
        if hello.get("type") != "hello-ok":
            await self.close()
            raise GatewayError(f"unexpected connect payload: {hello!r}")
        self.hello = hello
        auth = hello.get("auth") if isinstance(hello.get("auth"), dict) else {}
        if isinstance(auth.get("deviceToken"), str) and auth["deviceToken"]:
            self.issued_device_token = (auth["deviceToken"], list(auth.get("scopes") or scopes))
        return self

    @staticmethod
    def _connect_params(
        token: str | None,
        scopes: list[str],
        identity: DeviceIdentity | None,
        challenge: Challenge,
        *,
        password: str | None = None,
    ) -> dict[str, Any]:
        """``password``: the gateway's shared password. A team gateway in ``trusted-proxy`` mode
        takes people's identity from proxy headers and lets same-host services (this sensor)
        authenticate with ``gateway.auth.password`` instead; a token is not allowed there."""
        platform = sys.platform
        auth: dict[str, str] = {}
        if password:
            auth["password"] = password
        signature_token = ""
        if token:
            auth["token"] = signature_token = token
        elif identity is not None and identity.device_token:
            auth["deviceToken"] = signature_token = identity.device_token
            scopes = list(identity.token_scopes) or scopes  # a device token can't widen its pairing
        params: dict[str, Any] = {
            "minProtocol": MIN_PROTOCOL,
            "maxProtocol": MAX_PROTOCOL,
            "client": {
                "id": CLIENT_ID,
                "version": "sg-advance",
                "platform": platform,
                "mode": CLIENT_MODE,
            },
            "role": "operator",
            "scopes": scopes,
            "caps": CAPS,
            "commands": [],
            "permissions": {},
            "locale": "en-US",
            "userAgent": "sg-advance",
        }
        if auth:
            params["auth"] = auth
        if identity is not None:
            params["device"] = identity.connect_block(
                token=signature_token,
                nonce=challenge.nonce,
                role="operator",
                scopes=scopes,
                platform=platform,
                signed_at=challenge.ts,
            )
        return params

    @staticmethod
    async def _await_challenge(ws: Any, timeout: float) -> Challenge:
        async def wait() -> Challenge:
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
                    p = msg.get("payload") or {}
                    nonce, ts = p.get("nonce"), p.get("ts")
                    if isinstance(nonce, str) and nonce:
                        valid_ts = isinstance(ts, int) and not isinstance(ts, bool) and ts >= 0
                        return Challenge(nonce, ts if valid_ts else None)
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

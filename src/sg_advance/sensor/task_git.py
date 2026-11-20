"""The endpoint side of the Git gateway (2026-11-18, docs/git-gateway.md).

An agent's ``git`` talks to a loopback proxy in the sensor daemon::

    git remote: http://127.0.0.1:<port>/git/<project>.git
    git credential helper → the task grant (from a private grant file) as the HTTP password

The proxy adds the device credential (enrolled token, and the device certificate over mTLS when enrolled
that way) and forwards to the control plane's ``/v1/resources/git``; the agent never holds the device
credential. The control plane decides; this proxy only carries. A request without a grant gets 401 so git
asks its credential helper.

    python -m sg_advance.sensor.task_git credential --grant-file F get    # git credential helper

Same-user limits apply (CLAUDE.md): a process running as the person can read the device credential file
too. The proxy keeps the credential out of the agent's configuration and environment, not out of reach.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import http.client
import logging
import os
import re
import ssl
import stat
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .adapters.base import AdapterContext
from .adapters.mcp_gateway import HttpError, body_chunks, read_head

log = logging.getLogger(__name__)

MAX_BODY = 32 * 1024 * 1024
PATH = re.compile(
    r"^/git/([A-Za-z0-9][A-Za-z0-9._-]{0,99})\.git/(info/refs|git-upload-pack|git-receive-pack)$"
)
FORWARD = ("content-type", "content-encoding", "accept", "user-agent")
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def read_grant(path: Path) -> str:
    """A private regular file holding one task grant (the same rule as the task MCP bridge)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16384:
            raise ValueError("a private regular task grant file is required")
        return stream.read(16385).decode("ascii").strip()


def _reply(status: int, reason: str, body: bytes = b"", headers: dict[str, str] | None = None) -> bytes:
    head = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{k}: {v}" for k, v in (headers or {}).items()]
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


class GitProxyAdapter:
    name = "git_proxy"

    def __init__(
        self,
        host: str,
        port: int,
        server_url: str,
        device_token: str,
        upstream_ssl: ssl.SSLContext | None = None,
    ) -> None:
        if host not in LOOPBACK:
            raise ValueError("the Git proxy listens on loopback only")
        self.host, self.port = host, port
        self.upstream = urlsplit(server_url.rstrip("/"))
        self.device_token = device_token
        self.upstream_ssl = upstream_ssl
        self._server: asyncio.base_events.Server | None = None
        self._ctx: AdapterContext | None = None

    async def start(self, ctx: AdapterContext | None = None) -> None:
        self._ctx = ctx
        self._server = await asyncio.start_server(self._client, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("git proxy listening on %s:%d → %s", self.host, self.port, self.upstream.netloc)

    async def run(self, ctx: AdapterContext) -> None:
        await self.start(ctx)
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(await self._handle(reader))
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def _handle(self, reader: asyncio.StreamReader) -> bytes:
        try:
            start, headers = await read_head(reader)
            method, target, _ = start.split(" ", 2)
            url = urlsplit(target)
            m = PATH.match(url.path)
            if m is None or method not in {"GET", "POST"} or (method == "GET") != (m.group(2) == "info/refs"):
                return _reply(404, "Not Found", b"not a protected repository path\n")
            query = ""
            if m.group(2) == "info/refs":
                service = parse_qs(url.query).get("service", [""])[0]
                if service not in {"git-upload-pack", "git-receive-pack"}:
                    return _reply(403, "Forbidden", b"unsupported git service\n")
                query = f"?service={service}"
            grant = self._grant(headers.get("authorization", ""))
            if grant is None:  # git then asks its credential helper for the task grant
                return _reply(401, "Unauthorized", b"task grant required\n",
                              {"WWW-Authenticate": 'Basic realm="SG-Advance task grant"'})  # fmt: skip
            service = query.removeprefix("?service=") or m.group(2)
            if (refused := self._without_hook(m.group(1), service, grant)) is not None:
                return refused
            body = b""
            if method == "POST":
                async for chunk in body_chunks(reader, headers, max_total=MAX_BODY):
                    body += chunk
        except (HttpError, ValueError):
            return _reply(400, "Bad Request", b"bad request\n")
        path = f"{self.upstream.path}/v1/resources/git/{m.group(1)}.git/{m.group(2)}{query}"
        forwarded = {k: headers[k] for k in FORWARD if k in headers}
        try:
            return await asyncio.to_thread(self._forward, method, path, forwarded, grant, body)
        except (OSError, http.client.HTTPException) as e:
            log.warning("git proxy upstream failed: %s", type(e).__name__)
            return _reply(502, "Bad Gateway", b"protected repository unavailable\n")

    def _without_hook(self, project: str, service: str, grant: str) -> bytes | None:
        """Hook coverage (2026-11-20 user decision): when the grant's session never reached this daemon
        through its agent's hook, the request is judged here (signed rule ``protected-resource-without-
        agent-hook``) before anything goes upstream. Covered sessions pass straight to the control plane,
        which judges every Git request itself, so nothing is recorded twice."""
        ctx = self._ctx
        claims = ctx.sensor.grant_claims(grant) if ctx is not None else None
        if ctx is None or claims is None:
            return None  # an unverifiable grant: the control plane refuses it
        labels = ctx.sensor.hook_coverage(grant)
        if labels.get("sga_hook_coverage") != "missing":
            return None
        from .decision import GIT_PROXY, judge_event
        from .envelope import envelope

        tool = "git_push" if service == "git-receive-pack" else "git_fetch"
        event = envelope(
            sensor="mcp_proxy",
            agent={"type": claims.agent_type, "session_id": claims.session_id},
            # No MCP provider: this is a Git request, not an MCP call (unapproved-mcp-tool-call fired on it).
            payload={"kind": "tool.call", "call_id": f"git:{uuid.uuid4().hex}", "tool": tool,
                     "arguments": {"project": project}},
            hostname=ctx.hostname,
            user_id=claims.user_id,
            labels={"sga_source": "git_proxy", **labels},
        )  # fmt: skip
        verdict = judge_event(ctx, event, GIT_PROXY)
        if verdict.get("decision") == "allow":
            return None
        reason = str(verdict.get("reason") or "SG-Advance: not allowed by policy")
        return _reply(403, "Forbidden", reason.encode() + b"\n")

    @staticmethod
    def _grant(authorization: str) -> str | None:
        if not authorization.lower().startswith("basic "):
            return None
        try:
            _, _, password = base64.b64decode(authorization[6:], validate=True).decode("ascii").partition(":")
        except (ValueError, UnicodeError):
            return None
        return password or None

    def _forward(self, method: str, path: str, headers: dict[str, str], grant: str, body: bytes) -> bytes:
        tls = self.upstream.scheme == "https"
        host, port = self.upstream.hostname or "", self.upstream.port or (443 if tls else 80)
        conn = (
            http.client.HTTPSConnection(host, port, context=self.upstream_ssl or ssl.create_default_context(),
                                        timeout=150)  # fmt: skip
            if tls
            else http.client.HTTPConnection(host, port, timeout=150)
        )
        try:
            conn.request(method, path, body=body or None, headers=headers | {
                "Authorization": f"Bearer {self.device_token}", "X-SGA-Task-Grant": grant,
                "Content-Length": str(len(body)),
            })  # fmt: skip
            response = conn.getresponse()
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                return _reply(502, "Bad Gateway", b"oversized upstream response\n")
            out = {"Content-Type": response.getheader("Content-Type", "application/octet-stream"),
                   "Cache-Control": "no-cache"}  # fmt: skip
            return _reply(response.status, response.reason or "", data, out)
        finally:
            conn.close()


def credential_main(argv: list[str]) -> int:
    """``git credential`` protocol: answer ``get`` with the task grant as the password; nothing to store."""
    p = argparse.ArgumentParser(prog="sga-task-git-credential")
    p.add_argument("--grant-file", type=Path, required=True)
    p.add_argument("operation", choices=["get", "store", "erase"])
    args = p.parse_args(argv)
    sys.stdin.read()  # protocol, host, path: the proxy decides where it goes, not this helper
    if args.operation != "get":
        return 0
    try:
        token = read_grant(args.grant_file)
    except (OSError, ValueError) as e:
        print(f"SG-Advance: no usable task grant ({type(e).__name__})", file=sys.stderr)
        return 1
    sys.stdout.write(f"username=sga-task\npassword={token}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["credential"]:
        return credential_main(argv[1:])
    print("usage: python -m sg_advance.sensor.task_git credential --grant-file F get", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

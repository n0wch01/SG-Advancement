"""Small stdio transport into the existing HTTP MCP gateway; contains no human/device credential."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from ..policy import load_public_key
from ..task_grants import verify_task

MAX_MESSAGE = 131072


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def exchange(gateway: str, grant_file: Path, public_key: str, message: dict) -> dict | None:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "SG-Advance-Task-MCP/1",
    }
    if grant_file.exists():
        fd = os.open(grant_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16384:
                raise ValueError("a private regular task grant file is required")
            token = stream.read(16385).decode("ascii").strip()
        claims = verify_task(token, load_public_key(public_key))
        headers["X-SGA-Task-Grant"] = token
        headers["Mcp-Session-Id"] = claims.session_id
        agent = "claude-code" if claims.agent_type == "claude_code" else "codex-cli"
        headers["User-Agent"] = f"SG-Advance-Task-MCP/1 ({agent})"
    request = urllib.request.Request(
        gateway, data=json.dumps(message, ensure_ascii=False).encode(), headers=headers, method="POST"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        raw = response.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise ValueError("oversized protected MCP response")
        if response.status in {202, 204} or not raw:
            return None
        result = json.loads(raw)
        if (not isinstance(result, dict) or result.get("jsonrpc") != "2.0"
                or result.get("id") != message.get("id") or (("result" in result) == ("error" in result))):
            raise ValueError("invalid protected MCP response")
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--grant-file", type=Path, required=True)
    parser.add_argument("--public-key", required=True, help="enrolled server Ed25519 public key (base64)")
    args = parser.parse_args(argv)
    if os.name != "posix":
        parser.error("this task MCP bridge is currently qualified for POSIX clients only")
    load_public_key(args.public_key)
    url = urlsplit(args.gateway)
    if (
        url.scheme not in {"http", "https"}
        or url.username
        or url.password
        or url.query
        or url.fragment
        or (url.scheme == "http" and url.hostname not in {"127.0.0.1", "localhost", "::1"})
    ):
        parser.error("use a fixed HTTPS gateway or a loopback HTTP gateway without credentials/query")
    while True:
        line = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
        if not line:
            return 0
        mid = None
        try:
            if len(line) > MAX_MESSAGE:
                raise ValueError("oversized MCP request")
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("individual MCP requests are required")
            mid = message.get("id")
            result = exchange(args.gateway, args.grant_file, args.public_key, message)
            if mid is not None and result is not None:
                print(json.dumps(result, ensure_ascii=False), flush=True)
        except Exception:
            # No raw request/response, auth headers or capability is printed on failures. A failed
            # write might have reached the upstream: never encourage automatic retries.
            if mid is not None:
                print(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "error": {
                                "code": -32001,
                                "message": (
                                    "Protected gateway unavailable or invalid response. "
                                    "Do not retry writes automatically."
                                ),
                            },
                        }
                    ),
                    flush=True,
                )
            else:
                print("SG-Advance task MCP transport failed", file=sys.stderr, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

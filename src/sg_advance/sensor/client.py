"""Minimal control-plane client on the standard library (sensors stay dependency-light).

The HTTP layer is a swappable ``Transport`` so tests can drive the real FastAPI app in-process.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..policy import PolicyBundle


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


# (method, url, headers, body) -> response. Raises OSError when the server can't be reached.
Transport = Callable[[str, str, dict[str, str], bytes | None], HttpResponse]


def urllib_transport(timeout: float = 10.0) -> Transport:
    def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL comes from config)
                return HttpResponse(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read())
        except urllib.error.HTTPError as e:  # 304 and every 4xx/5xx land here
            return HttpResponse(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read())

    return send


class Offline(Exception):
    """Control plane unreachable (network error, timeout, or 5xx)."""


class ControlPlaneError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


def _detail(r: HttpResponse) -> str:
    try:
        body = r.json()
    except ValueError:
        return r.body[:200].decode("utf-8", "replace")
    return str(body.get("detail", body)) if isinstance(body, dict) else str(body)


class ControlPlaneClient:
    def __init__(self, server_url: str, token: str | None = None, transport: Transport | None = None) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token
        self._send = transport or urllib_transport()

    def _call(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
        token: str | None = None,
    ) -> HttpResponse:
        h = {"Accept": "application/json", **(headers or {})}
        if (tok := token or self.token) is not None:
            h["Authorization"] = f"Bearer {tok}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            h["Content-Type"] = "application/json"
        try:
            r = self._send(method, self.server_url + path, h, data)
        except OSError as e:  # URLError, ConnectionRefused, timeouts
            raise Offline(str(e)) from e
        if r.status >= 500:
            raise Offline(f"HTTP {r.status}: {_detail(r)}")
        return r

    def _ok(self, r: HttpResponse, *expected: int) -> Any:
        if r.status not in expected:
            raise ControlPlaneError(r.status, _detail(r))
        return r.json()

    def health(self) -> dict[str, Any]:
        return self._ok(self._call("GET", "/healthz"), 200)

    def enroll(self, enrollment_token: str, **body: Any) -> dict[str, Any]:
        r = self._call(
            "POST", "/v1/enroll", {k: v for k, v in body.items() if v is not None}, token=enrollment_token
        )
        return self._ok(r, 201)

    def get_policy(self, current_version: str | None = None) -> PolicyBundle | None:
        """None means 304 (unchanged)."""
        headers = {"If-None-Match": f'"{current_version}"'} if current_version else None
        r = self._call("GET", "/v1/policy", headers=headers)
        if r.status == 304:
            return None
        return PolicyBundle.model_validate(self._ok(r, 200))

    def post(self, path: str, body: Any) -> dict[str, Any]:
        """Raw POST for the spool; it interprets status codes itself."""
        r = self._call("POST", path, body)
        return {"status": r.status, "body": r.json() if r.status == 200 else _detail(r)}

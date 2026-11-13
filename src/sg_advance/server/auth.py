"""Bearer-token auth for the control plane.

- Admin: one shared token from ``SGA_ADMIN_TOKEN``.
- Dashboard (M7): ``SGA_DASHBOARD_TOKEN``, read-only: the same /v1/admin routes, GET only. The web
  console logs in with it, so the browser never holds a token that can change policy or enroll devices.
- Sensor: a per-device token issued at enrollment. Only its sha256 is stored, so a leaked DB
  does not leak usable tokens. Tokens are 256-bit random, so a fast hash is sufficient.
- M12: a device enrolled over the LAN also holds a client certificate. The LAN gateway (nginx)
  verifies it and forwards it with the shared proxy secret; such a device is accepted only with its
  own certificate, so a leaked device token alone is not enough (T11). Revoked devices are refused.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterator
from typing import Annotated

from cryptography import x509
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..pki import fingerprint
from .db import Device, utcnow
from .device_ca import presented_certificate

ENROLL_PREFIX = "set_"  # SG-Advance enrollment token (prefix kept: existing tokens stay valid)
DEVICE_PREFIX = "sdt_"  # SG-Advance device token

_bearer = HTTPBearer(auto_error=False)


def new_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


def bearer_token(creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> str:
    if creds is None or not creds.credentials:
        raise _unauthorized("missing bearer token")
    return creds.credentials


def get_session(request: Request) -> Iterator[Session]:
    yield from request.app.state.db.session()


Token = Annotated[str, Depends(bearer_token)]
DbSession = Annotated[Session, Depends(get_session)]


READ_METHODS = frozenset({"GET", "HEAD"})


def _matches(token: str, expected: str | None) -> bool:
    return bool(expected) and hmac.compare_digest(token.encode(), expected.encode())  # type: ignore[union-attr]


def require_admin(request: Request, token: Token) -> None:
    """Admin token for everything; the dashboard token for reads. Sets ``request.state.role``."""
    settings = request.app.state.settings
    if _matches(token, settings.admin_token):
        request.state.role = "admin"
        return
    if _matches(token, settings.dashboard_token):
        if request.method not in READ_METHODS:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "the dashboard token is read-only")
        request.state.role = "viewer"
        return
    raise _unauthorized("invalid admin token")


PROXY_SECRET_HEADER = "x-sga-proxy-secret"
CLIENT_CERT_HEADER = "x-sga-client-cert"  # nginx $ssl_client_escaped_cert (verified)
ENTRY_HEADER = "x-sga-entry"  # "lan" when the request came in through the LAN gateway


def via_gateway(request: Request) -> bool:
    """The request came through the LAN gateway (its client-certificate headers can be trusted)."""
    given = request.headers.get(PROXY_SECRET_HEADER)
    return given is not None and _matches(given, request.app.state.settings.proxy_secret)


def client_certificate(request: Request) -> x509.Certificate | None:
    if not via_gateway(request):
        return None
    return presented_certificate(request.headers.get(CLIENT_CERT_HEADER), request.app.state.device_ca)


def require_device(request: Request, token: Token, db: DbSession) -> Device:
    if not token.startswith(DEVICE_PREFIX):
        raise _unauthorized("not a device token")
    device = db.scalar(select(Device).where(Device.token_hash == hash_token(token)))
    if device is None:
        raise _unauthorized("unknown device token")
    if device.revoked_at is not None:
        raise _unauthorized("device revoked")
    cert = client_certificate(request)
    if device.cert_fingerprint is not None:
        if cert is None or fingerprint(cert) != device.cert_fingerprint:
            raise _unauthorized("this device must present its own client certificate")
        if device.cert_not_after is not None and utcnow() >= device.cert_not_after:
            raise _unauthorized("client certificate expired; re-enroll the device")
    elif cert is not None or (via_gateway(request) and request.headers.get(ENTRY_HEADER) == "lan"):
        # A token-only device (enrolled inside the compose network) coming in over the LAN, or with
        # someone else's certificate: refuse rather than accept the token alone.
        raise _unauthorized("this device has no client certificate; enroll it over the LAN")
    return device

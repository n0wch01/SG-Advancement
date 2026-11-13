"""Per-request device check for the LAN gateway's MCP route (2026-11-13, zero trust).

nginx verifies the client certificate against the device CA, but it does not know which devices
security revoked. For every ``/mcp/`` request it asks here first (``auth_request``): the certificate
must belong to an enrolled, unrevoked device whose certificate has not expired. The answer names the
device (``X-SGA-Device``), which nginx forwards to the central MCP gateway. Revoking a device in the
console therefore cuts its agents off the company's MCP servers on the next request
(KISA agentic AI ZT guide P1-3 continuous verification, P5-6).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from ..pki import fingerprint
from .auth import DbSession, client_certificate
from .db import Device, utcnow

router = APIRouter(prefix="/v1/gateway", tags=["gateway"])


@router.get("/authz", status_code=status.HTTP_204_NO_CONTENT)
def authz(request: Request, db: DbSession) -> Response:
    cert = client_certificate(request)  # None unless it came through the LAN gateway with its secret
    if cert is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "device certificate required")
    device = db.scalar(select(Device).where(Device.cert_fingerprint == fingerprint(cert)))
    now = utcnow()
    if device is None or device.revoked_at is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "unknown or revoked device")
    if device.cert_not_after is not None and now >= device.cert_not_after:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "device certificate expired")
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"X-SGA-Device": device.device_id})

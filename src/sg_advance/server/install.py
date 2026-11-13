"""One-line sensor install served by the control plane (M12, decision 2026-11-13: no GitHub, no
internet needed for our own code; the version the company runs is the one served here).

    GET /install/install.ps1        the Windows installer, with this server's addresses and hashes
    GET /install/ca.pem             the device CA
    GET /install/requirements.txt   the sensor's dependencies, every one pinned by hash
    GET /install/<wheel>            the sensor itself
    GET /install/sg-advance-plugin.zip   the OpenClaw gateway plugin (installed when the PC runs OpenClaw)

Other PCs reach these on the LAN gateway's plain-HTTP port. Nothing here is secret, and nothing is
trusted for being here: the install command carries the installer's SHA-256, the installer carries
every other file's SHA-256 and the CA fingerprint. Tampering on the way stops the install.

``POST /v1/admin/install-command`` makes a one-time enrollment token and the command to paste into
PowerShell on the new PC (``sga-server device install``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from ..pki import cert_pem
from .auth import DbSession, require_admin

TEMPLATE = Path(__file__).with_name("install.ps1")
DEVICE_ID = r"^[a-z0-9][a-z0-9._-]{0,63}$"

router = APIRouter(prefix="/install", tags=["install"])
admin = APIRouter(prefix="/v1/admin", tags=["install"], dependencies=[Depends(require_admin)])


PLUGIN_ZIP = "sg-advance-plugin.zip"
PLUGIN_FILES = ("index.ts", "policy.ts", "package.json", "openclaw.plugin.json")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def plugin_zip(plugin_dir: Path | None) -> bytes | None:
    """The plugin's runtime files, zipped reproducibly (fixed times, fixed order): same files, same hash."""
    if plugin_dir is None or not all((plugin_dir / f).is_file() for f in PLUGIN_FILES):
        return None
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in PLUGIN_FILES:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            z.writestr(info, (plugin_dir / name).read_bytes())
    return buf.getvalue()


@dataclass(frozen=True)
class Bundle:
    wheel: Path
    requirements: Path


def bundle(install_dir: Path | None) -> Bundle:
    if install_dir is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "no sensor build configured (SGA_INSTALL_DIR)"
        )
    wheels = sorted(install_dir.glob("sg_advance-*.whl"))
    req = install_dir / "requirements.txt"
    if len(wheels) != 1 or not req.exists():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"expected one sensor wheel and requirements.txt in {install_dir}",
        )
    return Bundle(wheels[0], req)


def render(request: Request) -> str:
    settings = request.app.state.settings
    if not settings.lan_url or not settings.install_url:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "set SGA_LAN_URL and SGA_INSTALL_URL (docs/multi-host.md)"
        )
    b = bundle(settings.install_dir)
    ca = request.app.state.device_ca
    values = {
        "LAN_URL": settings.lan_url.rstrip("/"),
        "INSTALL_URL": settings.install_url.rstrip("/"),
        "CA_FINGERPRINT": ca.fingerprint,
        "CA_FILE_SHA256": sha256(cert_pem(ca.cert).encode()),
        "WHEEL": b.wheel.name,
        "WHEEL_SHA256": sha256(b.wheel.read_bytes()),
        "REQ_SHA256": sha256(b.requirements.read_bytes()),
        "PLUGIN_SHA256": sha256(z) if (z := plugin_zip(settings.plugin_dir)) else "",
    }
    text = TEMPLATE.read_text("ascii")
    for k, v in values.items():
        text = text.replace(f"@@{k}@@", v)
    return text.replace("\r\n", "\n").replace("\n", "\r\n")  # PowerShell-native line endings, stable hash


def command(script: str, install_url: str, token: str, device_id: str | None, user: str | None) -> str:
    """One PowerShell line: fetch the installer, refuse it unless its SHA-256 matches, run it."""
    digest = sha256(script.encode("ascii")).upper()
    env = f"$env:SGA_ENROLL_TOKEN='{token}'; "
    if device_id:
        env += f"$env:SGA_DEVICE_ID='{device_id}'; "
    if user:
        env += f"$env:SGA_USER='{user}'; "
    url = f"{install_url.rstrip('/')}/install/install.ps1"
    return (
        f"{env}$s=(Invoke-WebRequest -UseBasicParsing {url}).Content; "
        "$h=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash("
        "[Text.Encoding]::ASCII.GetBytes($s))).Replace('-',''); "
        f"if($h -ne '{digest}'){{throw 'install.ps1 does not match the pinned SHA-256: not running it'}}; "
        "Invoke-Expression $s"
    )


# ── files ───────────────────────────────────────────────────────────────────


@router.get("/install.ps1", response_class=PlainTextResponse)
def installer(request: Request) -> Response:
    return PlainTextResponse(render(request), media_type="text/plain; charset=us-ascii")


@router.get("/ca.pem", response_class=PlainTextResponse)
def ca_file(request: Request) -> Response:
    return PlainTextResponse(cert_pem(request.app.state.device_ca.cert), media_type="application/x-pem-file")


@router.get("/requirements.txt")
def requirements(request: Request) -> Response:
    return FileResponse(bundle(request.app.state.settings.install_dir).requirements, media_type="text/plain")


@router.get(f"/{PLUGIN_ZIP}")
def plugin(request: Request) -> Response:
    z = plugin_zip(request.app.state.settings.plugin_dir)
    if z is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no plugin configured (SGA_PLUGIN_DIR)")
    return Response(z, media_type="application/zip")


@router.get("/{name}")
def wheel(name: str, request: Request) -> Response:
    b = bundle(request.app.state.settings.install_dir)
    if name != b.wheel.name:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return FileResponse(b.wheel, media_type="application/octet-stream", filename=b.wheel.name)


# ── admin ───────────────────────────────────────────────────────────────────


class InstallCommandIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(default=None, max_length=200)
    group: str | None = None
    device_id: str | None = Field(default=None, pattern=DEVICE_ID)
    user: str | None = Field(default=None, max_length=200, pattern=r"^[^'\s]+$")
    ttl_hours: float = Field(default=24, gt=0, le=24 * 30)


class InstallCommandOut(BaseModel):
    command: str = Field(
        description="Paste into PowerShell on the new PC. Holds a one-time token: shown once"
    )
    token_id: int
    expires_at: datetime
    installer_sha256: str
    ca_fingerprint: str


@admin.post("/install-command", response_model=InstallCommandOut, status_code=status.HTTP_201_CREATED)
def install_command(body: InstallCommandIn, request: Request, db: DbSession) -> InstallCommandOut:
    from .app import EnrollmentTokenRequest, create_enrollment_token  # app imports this module

    if request.state.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "install commands need the admin token")
    script = render(request)  # before spending a token: fails if the server is not set up for it
    tok = create_enrollment_token(
        EnrollmentTokenRequest(
            label=body.label or body.device_id, ttl_hours=body.ttl_hours, group=body.group
        ),
        db,
    )
    return InstallCommandOut(
        command=command(script, request.app.state.settings.install_url, tok.token, body.device_id, body.user),
        token_id=tok.id or 0,
        expires_at=tok.expires_at,
        installer_sha256=sha256(script.encode("ascii")),
        ca_fingerprint=request.app.state.device_ca.fingerprint,
    )

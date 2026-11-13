"""On-disk sensor state under ``SGA_HOME`` (default ``~/.sg-advance``).

credentials.json   device id/token, server URL, trusted policy key   (0600)
policy.json        last signed policy bundle (verified again on every load)
spool.db           outbound queue of events/findings (see spool.py)
ca.pem             device CA the control plane's LAN gateway is signed by (M12)
device.pem         this device's client certificate (M12)
device-key.pem     its private key, made here and never sent anywhere (0600)
"""

from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

DEFAULT_HOME = Path("~/.sg-advance")


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    server_url: str
    device_id: str
    device_token: str
    policy_public_key: str = Field(description="base64 Ed25519 key that policy bundles must verify against")
    policy_key_id: str
    key_pinned: bool = Field(
        description="True: key was given at install time (B). False: learned at enroll (A)"
    )
    enrolled_at: AwareDatetime
    client_certificate: bool = Field(
        default=False, description="M12: talks to the control plane with device.pem/device-key.pem (mTLS)"
    )


def write_private(path: Path, data: str) -> None:
    """Write a file readable by the owner only, atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


class SensorHome:
    def __init__(self, root: Path | None = None) -> None:
        env = os.environ.get("SGA_HOME")
        self.root = (root or (Path(env) if env else DEFAULT_HOME)).expanduser()

    @property
    def credentials_path(self) -> Path:
        return self.root / "credentials.json"

    @property
    def policy_path(self) -> Path:
        return self.root / "policy.json"

    @property
    def spool_path(self) -> Path:
        return self.root / "spool.db"

    @property
    def ca_path(self) -> Path:
        return self.root / "ca.pem"

    @property
    def cert_path(self) -> Path:
        return self.root / "device.pem"

    @property
    def key_path(self) -> Path:
        return self.root / "device-key.pem"

    def ssl_context(self) -> ssl.SSLContext | None:
        """TLS for an https control plane: trust only the pinned device CA, present the device
        certificate when there is one. None: plain http (inside the compose network)."""
        if not self.ca_path.exists():
            return None
        ctx = ssl.create_default_context(cafile=str(self.ca_path))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.cert_path.exists() and self.key_path.exists():
            ctx.load_cert_chain(str(self.cert_path), str(self.key_path))
        return ctx

    def load_credentials(self) -> Credentials | None:
        p = self.credentials_path
        return Credentials.model_validate_json(p.read_text("utf-8")) if p.exists() else None

    def save_credentials(self, creds: Credentials) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(self.credentials_path, creds.model_dump_json(indent=2))


def now_utc() -> datetime:
    return datetime.now(UTC)

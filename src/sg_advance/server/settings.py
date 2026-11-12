"""Control plane configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB_URL = "sqlite:///data/sga.db"
DEFAULT_RULES_DIR = "rules"
DEFAULT_SIGNING_KEY = "data/policy_signing_key.pem"


@dataclass(frozen=True)
class Settings:
    db_url: str = DEFAULT_DB_URL
    rules_dir: Path = Path(DEFAULT_RULES_DIR)
    admin_token: str | None = None
    # SGA-Dashboard (M7): a read-only token for the web console, so the browser never holds the
    # admin token. GET requests to /v1/admin only. None: the dashboard needs the admin token.
    dashboard_token: str | None = None
    dashboard_dir: Path | None = None  # built dashboard (dashboard/dist), served at /dashboard
    signing_key_path: Path = Path(DEFAULT_SIGNING_KEY)
    max_batch: int = 500
    # M5d package verification: npm registry signature + Sigstore provenance → known-good digests.
    release_cooldown_days: float = 3.0  # verified releases are trusted only after this long
    auto_verify: bool = True  # verify versions sensors report, without waiting for an admin
    npm_registry: str = "https://registry.npmjs.org"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_url=os.environ.get("SGA_DB_URL", DEFAULT_DB_URL),
            rules_dir=Path(os.environ.get("SGA_RULES_DIR", DEFAULT_RULES_DIR)),
            admin_token=os.environ.get("SGA_ADMIN_TOKEN") or None,
            dashboard_token=os.environ.get("SGA_DASHBOARD_TOKEN") or None,
            dashboard_dir=Path(d) if (d := os.environ.get("SGA_DASHBOARD_DIR")) else None,
            signing_key_path=Path(os.environ.get("SGA_SIGNING_KEY", DEFAULT_SIGNING_KEY)),
            max_batch=int(os.environ.get("SGA_MAX_BATCH", "500")),
            release_cooldown_days=float(os.environ.get("SGA_RELEASE_COOLDOWN_DAYS", "3")),
            auto_verify=os.environ.get("SGA_AUTO_VERIFY", "1") not in ("0", "false", "no"),
            npm_registry=os.environ.get("SGA_NPM_REGISTRY", "https://registry.npmjs.org"),
        )

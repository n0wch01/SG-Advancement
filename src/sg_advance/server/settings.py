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
    signing_key_path: Path = Path(DEFAULT_SIGNING_KEY)
    max_batch: int = 500

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_url=os.environ.get("SGA_DB_URL", DEFAULT_DB_URL),
            rules_dir=Path(os.environ.get("SGA_RULES_DIR", DEFAULT_RULES_DIR)),
            admin_token=os.environ.get("SGA_ADMIN_TOKEN") or None,
            signing_key_path=Path(os.environ.get("SGA_SIGNING_KEY", DEFAULT_SIGNING_KEY)),
            max_batch=int(os.environ.get("SGA_MAX_BATCH", "500")),
        )

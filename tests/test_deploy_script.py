"""scripts/deploy.sh: the deploy order that has worked, as one command (dry run only here)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def dry(*args: str) -> str:
    env = os.environ | {"SGA_ADMIN_TOKEN": "secret-must-not-print"}
    out = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", *args], capture_output=True, text=True, env=env, check=True
    )
    return out.stdout + out.stderr


def test_steps_run_in_the_order_that_worked() -> None:
    out = dry("--label", "pre-test")
    order = [
        "/data/sga.db.pre-test",  # backup before anything changes
        "npm --prefix dashboard run build",
        "docker compose up -d --build control-plane",
        "launchctl kickstart -k",
        "docker compose --profile team build team-gateway",
        "up -d --no-build team-gateway team-audit team-egress carol-pc mcp-gateway corp-crm",
        "--force-recreate --no-deps lan-gateway",
        "nginx -t",
        "/v1/admin/devices",
    ]
    at = [out.index(s) for s in order]
    assert at == sorted(at), out
    assert "secret-must-not-print" not in out


def test_skips_and_label_validation() -> None:
    out = dry("--no-dashboard", "--no-team")
    assert "npm" not in out and "team-gateway" not in out
    assert "docker compose up -d --build control-plane" in out
    bad = subprocess.run(["bash", str(SCRIPT), "--dry-run", "--label", "x;rm -rf /"], capture_output=True)
    assert bad.returncode == 2  # the label ends up in a path inside the container

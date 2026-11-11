"""sga-sensor CLI over real HTTP (uvicorn on a free port) — exercises the urllib transport."""

from __future__ import annotations

import shutil
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient

from sg_advance.sensor.cli import main
from sg_advance.server import Settings, create_app

ROOT = Path(__file__).resolve().parents[1]
ADMIN = {"Authorization": "Bearer admin-test"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live(tmp_path: Path) -> Iterator[tuple[str, TestClient]]:
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    app = create_app(
        Settings(
            db_url=f"sqlite:///{tmp_path / 'cp.db'}",
            rules_dir=rules,
            admin_token="admin-test",
            signing_key_path=tmp_path / "key.pem",
        )
    )
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}", TestClient(app)  # TestClient only for admin reads
    finally:
        server.should_exit = True
        t.join(timeout=5)


def test_cli_enroll_replay_status_sync(
    live: tuple[str, TestClient],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, admin = live
    home = ["--home", str(tmp_path / "home")]
    token = admin.post("/v1/admin/enrollment-tokens", json={}, headers=ADMIN).json()["token"]
    monkeypatch.setenv("SGA_ENROLL_TOKEN", token)

    assert main([*home, "enroll", "--server", url, "--device-id", "dev-bob"]) == 0
    assert "enrolled as dev-bob" in capsys.readouterr().out

    assert main([*home, "replay", str(ROOT / "examples/events/claude_code.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "policy: updated" in out
    assert "sensitive-file-access" in out
    assert "remaining 0" in out

    assert main([*home, "sync"]) == 0
    assert "policy: unchanged" in capsys.readouterr().out  # 304 through urllib

    assert main([*home, "status"]) == 0
    out = capsys.readouterr().out
    assert "dev-bob" in out and "trust on first use" in out and "0 events" in out

    findings = admin.get("/v1/admin/findings", params={"device_id": "dev-bob"}, headers=ADMIN).json()
    assert {f["rule_id"] for f in findings} >= {"sensitive-file-access"}


def test_cli_reports_offline_and_keeps_queue(
    live: tuple[str, TestClient], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, admin = live
    home = ["--home", str(tmp_path / "home")]
    token = admin.post("/v1/admin/enrollment-tokens", json={}, headers=ADMIN).json()["token"]
    assert main([*home, "enroll", "--server", url, "--token", token]) == 0
    assert main([*home, "sync"]) == 0
    capsys.readouterr()

    # Point the sensor at a dead port: detection still runs on the cached policy.
    cred = tmp_path / "home" / "credentials.json"
    cred.write_text(cred.read_text().replace(url, f"http://127.0.0.1:{_free_port()}"))
    assert main([*home, "replay", str(ROOT / "examples/events/claude_code.jsonl")]) == 1
    out = capsys.readouterr().out
    assert "policy: offline" in out and "offline" in out.splitlines()[-1]
    assert main([*home, "status"]) == 0
    assert "0 events" not in capsys.readouterr().out


def test_cli_without_enrollment(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--home", str(tmp_path / "nothing"), "status"]) == 1
    assert "not enrolled" in capsys.readouterr().err

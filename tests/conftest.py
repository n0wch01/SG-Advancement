"""Shared fixtures: an in-process control plane and an enrolled sensor talking to it."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sg_advance.sensor import Sensor, SensorHome, enroll
from sg_advance.sensor.client import HttpResponse
from sg_advance.server import Settings, create_app

ROOT = Path(__file__).resolve().parents[1]
CP_URL = "http://testserver"
CP_ADMIN = {"Authorization": "Bearer admin-test"}


class CpTransport:
    """Sensor HTTP transport into the in-process app; ``down`` simulates an outage."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.down = False

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
        if self.down:
            raise ConnectionRefusedError("control plane down")
        r = self.client.request(method, url.removeprefix(CP_URL), headers=headers, content=body)
        return HttpResponse(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


@pytest.fixture
def cp(tmp_path: Path) -> Iterator[TestClient]:
    rules = tmp_path / "cp-rules"
    shutil.copytree(ROOT / "rules", rules)
    settings = Settings(
        db_url="sqlite://",
        rules_dir=rules,
        admin_token="admin-test",
        signing_key_path=tmp_path / "cp-key.pem",
    )
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def cp_transport(cp: TestClient) -> CpTransport:
    return CpTransport(cp)


@pytest.fixture
def enrolled(cp: TestClient, cp_transport: CpTransport, tmp_path: Path) -> Sensor:
    """A sensor enrolled as dev-alice with a policy already loaded."""
    home = SensorHome(tmp_path / "sensor")
    token = cp.post("/v1/admin/enrollment-tokens", json={}, headers=CP_ADMIN).json()["token"]
    enroll(home, CP_URL, token, device_id="dev-alice", transport=cp_transport)
    sensor = Sensor(home, transport=cp_transport)
    sensor.start()
    return sensor

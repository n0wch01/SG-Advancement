"""M12 one-line install: the control plane serves the sensor, the installer pins every file, the
install command pins the installer; and the Windows logon task the installer registers."""

from __future__ import annotations

import dataclasses
import hashlib
import re
from pathlib import Path, PureWindowsPath

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN
from sg_advance.pki import cert_pem
from sg_advance.sensor import service

WHEEL = "sg_advance-0.1.0-py3-none-any.whl"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def served(cp: TestClient, tmp_path: Path) -> TestClient:
    d = tmp_path / "install"
    d.mkdir()
    (d / WHEEL).write_bytes(b"PK fake wheel")
    (d / "requirements.txt").write_text("pydantic==2.11.0 \\\n    --hash=sha256:abc\n")
    cp.app.state.settings = dataclasses.replace(
        cp.app.state.settings,
        install_dir=d,
        lan_url="https://192.168.0.9:18443",
        install_url="http://192.168.0.9:18080",
        dashboard_token="view",
    )
    return cp


def test_installer_pins_every_file_it_downloads(served: TestClient) -> None:
    r = served.get("/install/install.ps1")
    assert r.status_code == 200
    script = r.content.decode("ascii")  # ASCII only: the one-liner hashes the text as ASCII
    assert "@@" not in script and "\r\n" in script and "\n" not in script.replace("\r\n", "")
    ca = served.app.state.device_ca
    files = {
        "ca.pem": served.get("/install/ca.pem").content,
        "requirements.txt": served.get("/install/requirements.txt").content,
        WHEEL: served.get(f"/install/{WHEEL}").content,
    }
    assert files["ca.pem"].decode() == cert_pem(ca.cert) and files[WHEEL] == b"PK fake wheel"
    assert f"$CaFileSha256  = '{sha(files['ca.pem'])}'" in script
    assert f"$ReqSha256     = '{sha(files['requirements.txt'])}'" in script
    assert f"$WheelSha256   = '{sha(files[WHEEL])}'" in script
    assert f"$CaFingerprint = '{ca.fingerprint}'" in script
    assert "$LanUrl        = 'https://192.168.0.9:18443'" in script
    assert "--require-hashes" in script and "--ca-sha256 $CaFingerprint" in script
    assert served.get("/install/other.whl").status_code == 404


def test_install_command_pins_the_installer_and_spends_one_token(served: TestClient) -> None:
    body = {"device_id": "laptop", "user": "gamer"}
    assert (
        served.post(
            "/v1/admin/install-command", json=body, headers={"Authorization": "Bearer view"}
        ).status_code
        == 403
    )
    r = served.post("/v1/admin/install-command", json=body, headers=CP_ADMIN)
    assert r.status_code == 201, r.text
    out = r.json()
    cmd = out["command"]
    script = served.get("/install/install.ps1").content
    pinned = re.search(r"if\(\$h -ne '([0-9A-F]{64})'\)", cmd)
    assert pinned and pinned.group(1) == sha(script).upper() == out["installer_sha256"].upper()
    assert "$env:SGA_DEVICE_ID='laptop'" in cmd and "$env:SGA_USER='gamer'" in cmd
    token = re.search(r"SGA_ENROLL_TOKEN='(set_[^']+)'", cmd)
    assert token
    listed = {t["id"]: t for t in served.get("/v1/admin/enrollment-tokens", headers=CP_ADMIN).json()}
    assert listed[out["token_id"]]["usable"] and listed[out["token_id"]]["label"] == "laptop"
    # Quotes or spaces in the user would break out of the PowerShell string: refused.
    bad = served.post("/v1/admin/install-command", json={"user": "x'; calc"}, headers=CP_ADMIN)
    assert bad.status_code == 422


def test_without_a_sensor_build_nothing_is_offered(cp: TestClient) -> None:
    assert cp.get("/install/install.ps1").status_code == 503
    assert cp.post("/v1/admin/install-command", json={}, headers=CP_ADMIN).status_code == 503
    assert cp.get("/v1/admin/enrollment-tokens", headers=CP_ADMIN).json() == []  # no token spent


def test_windows_logon_task_runs_the_sensor_windowless() -> None:
    home = Path("C:/Users/gamer/.sg-advance")
    scripts = Path("C:/Users/gamer/AppData/Local/SG-Advance/venv/Scripts")
    xml = service.windows_task_xml(home, ["--user", "gamer"], "LAPTOP\\gamer", scripts)
    assert "<LogonTrigger>" in xml and "<UserId>LAPTOP\\gamer</UserId>" in xml
    assert "<RunLevel>LeastPrivilege</RunLevel>" in xml and "<Count>999</Count>" in xml
    assert PureWindowsPath(re.search(r"<Command>(.+)</Command>", xml).group(1)).name == "pythonw.exe"  # type: ignore[union-attr]
    assert "-m sg_advance.sensor.cli --home" in xml and "run --user gamer --log-file" in xml
    vbs = service.startup_launcher(home, ["--user", "gamer"], scripts)
    assert vbs.startswith('CreateObject("WScript.Shell").Run "') and vbs.rstrip().endswith(", 0, False")


def test_plugin_is_zipped_reproducibly_and_pinned(served: TestClient) -> None:
    root = Path(__file__).resolve().parents[1] / "integrations" / "openclaw-plugin"
    served.app.state.settings = dataclasses.replace(served.app.state.settings, plugin_dir=root)
    a, b = served.get("/install/sg-advance-plugin.zip"), served.get("/install/sg-advance-plugin.zip")
    assert a.status_code == 200 and a.content == b.content  # same files, same bytes, same hash
    import io
    import zipfile

    names = zipfile.ZipFile(io.BytesIO(a.content)).namelist()
    assert names == ["index.ts", "policy.ts", "package.json", "openclaw.plugin.json"]  # no tests
    script = served.get("/install/install.ps1").text
    assert f"$PluginSha256  = '{sha(a.content)}'" in script
    assert "plugins install --link $PluginDir" in script and "openclaw-token" in script

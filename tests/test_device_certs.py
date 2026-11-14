"""M12 device certificates: CSR enrollment over the LAN gateway, certificate-bound device tokens,
revocation. The LAN gateway (nginx, mTLS) is simulated by a transport that adds the headers nginx
adds after verifying a client certificate."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from conftest import CP_ADMIN, CP_URL
from sg_advance.pki import CertificateAuthority, cert_pem, fingerprint, make_csr, new_key
from sg_advance.sensor import Sensor
from sg_advance.sensor.client import HttpResponse
from sg_advance.sensor.core import SensorError, enroll
from sg_advance.sensor.state import SensorHome

LAN_URL = "https://192.168.0.10:8443"
SECRET = "proxy-test-secret"
WHO = {"by": "secops@corp.test", "reason": "laptop stolen"}


class Gateway:
    """What nginx forwards: the proxy secret, the entry, and the verified client certificate."""

    def __init__(self, cp: TestClient, cert: Path | str | None = None, secret: str = SECRET) -> None:
        self.cp, self.cert, self.secret = cp, cert, secret

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
        h = dict(headers) | {"X-SGA-Proxy-Secret": self.secret, "X-SGA-Entry": "lan"}
        if self.cert is not None:
            pem = self.cert.read_text() if isinstance(self.cert, Path) else self.cert
            h["X-SGA-Client-Cert"] = quote(pem)
        path = url.removeprefix(LAN_URL).removeprefix(CP_URL)
        r = self.cp.request(method, path, headers=h, content=body)
        return HttpResponse(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)


@pytest.fixture
def lan(cp: TestClient, tmp_path: Path) -> TestClient:
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, proxy_secret=SECRET)
    (tmp_path / "ca.pem").write_text(cert_pem(cp.app.state.device_ca.cert))
    return cp


def token(cp: TestClient) -> tuple[int, str]:
    r = cp.post("/v1/admin/enrollment-tokens", json={"label": "laptop"}, headers=CP_ADMIN).json()
    return r["id"], r["token"]


def enroll_laptop(cp: TestClient, tmp_path: Path, device: str = "laptop") -> SensorHome:
    home = SensorHome(tmp_path / device)
    ca = cp.app.state.device_ca
    enroll(
        home, LAN_URL, token(cp)[1], device_id=device, transport=Gateway(cp),
        ca_file=tmp_path / "ca.pem", ca_sha256=ca.fingerprint,
    )  # fmt: skip
    return home


def test_ca_signs_device_and_server_certificates() -> None:
    ca = CertificateAuthority.create()
    key = new_key()
    cert = ca.sign_device(make_csr(key, "spoofed-name"), "laptop", days=30)
    assert cert.subject.rfc4514_string() == "CN=laptop"  # the CA decides the identity
    assert ca.issued(cert) and not CertificateAuthority.create().issued(cert)
    assert len(fingerprint(cert)) == 64
    server, _ = ca.sign_server(["192.168.0.10", "my-mac.local"], days=30)
    assert ca.issued(server)
    with pytest.raises(ValueError, match="PEM"):
        ca.sign_device("garbage", "x", days=1)


def test_lan_enrollment_binds_the_token_to_the_certificate(lan: TestClient, tmp_path: Path) -> None:
    home = enroll_laptop(lan, tmp_path)
    creds = home.load_credentials()
    assert creds is not None and creds.client_certificate and creds.server_url == LAN_URL
    assert home.key_path.exists() and (home.key_path.stat().st_mode & 0o777) == 0o600
    assert "BEGIN CERTIFICATE" in home.cert_path.read_text() and home.ca_path.exists()
    assert home.ssl_context() is not None

    # With its own certificate through the gateway: works.
    sensor = Sensor(home, transport=Gateway(lan, home.cert_path))
    assert sensor.sync_policy().value == "updated"
    dev = {d["device_id"]: d for d in lan.get("/v1/admin/devices", headers=CP_ADMIN).json()}["laptop"]
    assert dev["client_certificate"] is True and dev["cert_not_after"]

    auth = {"Authorization": f"Bearer {creds.device_token}"}
    # The token alone (leaked, used inside the network without the gateway): refused.
    assert lan.get("/v1/policy", headers=auth).status_code == 401
    # Through the gateway without a certificate, or with another device's certificate: refused.
    assert Gateway(lan)("GET", f"{LAN_URL}/v1/policy", auth, None).status == 401
    other = enroll_laptop(lan, tmp_path, "desktop")
    assert Gateway(lan, other.cert_path)("GET", f"{LAN_URL}/v1/policy", auth, None).status == 401
    # Certificate headers without the proxy secret count for nothing.
    forged = Gateway(lan, home.cert_path, secret="guess")
    assert forged("GET", f"{LAN_URL}/v1/policy", auth, None).status == 401
    # A certificate from some other CA is not ours, even if nginx were misconfigured.
    stranger = CertificateAuthority.create().sign_device(make_csr(new_key(), "laptop"), "laptop", 30)
    assert Gateway(lan, cert_pem(stranger))("GET", f"{LAN_URL}/v1/policy", auth, None).status == 401


def test_lan_enrollment_needs_a_csr_and_the_pinned_ca(lan: TestClient, tmp_path: Path) -> None:
    r = Gateway(lan)(
        "POST", f"{LAN_URL}/v1/enroll", {"Authorization": f"Bearer {token(lan)[1]}",
        "Content-Type": "application/json"}, b'{"device_id": "nocsr"}',
    )  # fmt: skip
    assert r.status == 400 and b"certificate request" in r.body

    wrong = tmp_path / "wrong-ca.pem"
    wrong.write_text(cert_pem(CertificateAuthority.create().cert))
    with pytest.raises(SensorError, match="does not match the pinned"):
        enroll(
            SensorHome(tmp_path / "x"), LAN_URL, token(lan)[1], transport=Gateway(lan),
            ca_file=wrong, ca_sha256=lan.app.state.device_ca.fingerprint,
        )  # fmt: skip
    # Pinned a CA that is not the server's: the server's answer is refused, nothing is saved.
    with pytest.raises(SensorError, match="pinned CA"):
        enroll(SensorHome(tmp_path / "y"), LAN_URL, token(lan)[1], transport=Gateway(lan), ca_file=wrong)
    assert not (tmp_path / "y" / "credentials.json").exists()


def test_token_only_devices_stay_inside_the_compose_network(lan: TestClient, enrolled: Sensor) -> None:
    auth = {"Authorization": f"Bearer {enrolled.creds.device_token}"}
    assert lan.get("/v1/policy", headers=auth).status_code == 200  # direct, as in compose
    assert Gateway(lan)("GET", f"{LAN_URL}/v1/policy", auth, None).status == 401  # not over the LAN


def test_revoking_a_device_or_an_enrollment_token(lan: TestClient, tmp_path: Path) -> None:
    home = enroll_laptop(lan, tmp_path)
    sensor = Sensor(home, transport=Gateway(lan, home.cert_path))
    assert sensor.sync_policy().value == "updated"
    viewer_lan = dataclasses.replace(lan.app.state.settings, dashboard_token="view")
    lan.app.state.settings = viewer_lan
    assert (
        lan.post(
            "/v1/admin/devices/laptop/revoke", json=WHO, headers={"Authorization": "Bearer view"}
        ).status_code
        == 403
    )
    r = lan.post("/v1/admin/devices/laptop/revoke", json=WHO, headers=CP_ADMIN)
    assert r.status_code == 200 and r.json()["revoked_by"] == "secops@corp.test"
    auth = {"Authorization": f"Bearer {sensor.creds.device_token}"}
    resp = Gateway(lan, home.cert_path)("GET", f"{LAN_URL}/v1/policy", auth, None)
    assert resp.status == 401 and b"revoked" in resp.body

    tid, tok = token(lan)
    assert lan.post(f"/v1/admin/enrollment-tokens/{tid}/revoke", headers=CP_ADMIN).status_code == 204
    listed = {t["id"]: t for t in lan.get("/v1/admin/enrollment-tokens", headers=CP_ADMIN).json()}
    assert listed[tid]["usable"] is False and listed[tid]["revoked_at"]
    with pytest.raises(Exception, match="invalid or expired"):
        enroll(
            SensorHome(tmp_path / "z"), LAN_URL, tok, transport=Gateway(lan),
            ca_file=tmp_path / "ca.pem",
        )  # fmt: skip


def test_mcp_route_authz_follows_enrollment_and_revocation(lan: TestClient, tmp_path: Path) -> None:
    """Zero trust (2026-11-13): nginx asks before every /mcp/ request. Enrolled device → 204 with its
    id; no certificate, a stranger's certificate, or no proxy secret → 403; revoked → 403 at once."""
    home = enroll_laptop(lan, tmp_path)

    def ask(cert: Path | str | None, secret: str = SECRET) -> HttpResponse:
        return Gateway(lan, cert, secret)("GET", f"{LAN_URL}/v1/gateway/authz", {}, None)

    ok = ask(home.cert_path)
    assert ok.status == 204 and ok.headers["x-sga-device"] == "laptop"
    assert ask(None).status == 403
    assert ask(home.cert_path, secret="wrong").status == 403
    stranger, _ = CertificateAuthority.create().sign_server(["x"], days=1)
    assert ask(cert_pem(stranger)).status == 403
    r = lan.post("/v1/admin/devices/laptop/revoke", json=WHO, headers=CP_ADMIN)
    assert r.status_code == 200, r.text
    assert ask(home.cert_path).status == 403


def test_an_owned_device_cannot_speak_for_someone_else(lan: TestClient, tmp_path: Path) -> None:
    """Review 2026-11-15: X-SGA-User passed through the LAN gateway untouched, so anything holding a
    laptop's certificate could act as any person on the company MCP servers (and slip past a remote
    block on its owner). A device with an owner now always speaks as that owner; without one, its claim
    is forwarded as before (the documented limit: a person's identity is what the device says)."""
    home = enroll_laptop(lan, tmp_path)

    def ask(claim: str | None) -> HttpResponse:
        headers = {"X-SGA-User": claim} if claim is not None else {}
        return Gateway(lan, home.cert_path)("GET", f"{LAN_URL}/v1/gateway/authz", headers, None)

    assert ask("bob@corp.test").headers.get("x-sga-user") == "bob@corp.test"  # no owner: the claim
    assert "x-sga-user" not in ask(None).headers or ask(None).headers["x-sga-user"] == ""
    body = {"owner": "alice@corp.test", **WHO}
    viewer = dataclasses.replace(lan.app.state.settings, dashboard_token="view")
    lan.app.state.settings = viewer
    view = {"Authorization": "Bearer view"}
    assert lan.post("/v1/admin/devices/laptop/owner", json=body, headers=view).status_code == 403
    r = lan.post("/v1/admin/devices/laptop/owner", json=body, headers=CP_ADMIN)
    assert r.status_code == 200 and r.json()["owner"] == "alice@corp.test"
    assert ask("mallory-blocked@corp.test").headers["x-sga-user"] == "alice@corp.test"  # owner wins
    assert ask(None).headers["x-sga-user"] == "alice@corp.test"
    cleared = lan.post("/v1/admin/devices/laptop/owner", json={"owner": None, **WHO}, headers=CP_ADMIN)
    assert cleared.json()["owner"] is None
    assert ask("bob@corp.test").headers["x-sga-user"] == "bob@corp.test"
    assert lan.post("/v1/admin/devices/nope/owner", json=body, headers=CP_ADMIN).status_code == 404


def test_the_lan_gateway_forwards_the_checked_person_not_the_clients_header() -> None:
    conf = (Path(__file__).resolve().parents[1] / "deploy/lan-gateway/default.conf.template").read_text()
    mcp = conf[conf.index("location /mcp/"):]
    mcp = mcp[: mcp.index("}") + 1] if "location /v1/" not in mcp else mcp[: mcp.index("location /v1/")]
    assert "auth_request_set $sga_user $upstream_http_x_sga_user;" in mcp
    assert "proxy_set_header X-SGA-User         $sga_user;" in mcp

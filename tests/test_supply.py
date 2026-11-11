"""Package verification (server/supply.py) and the shared digest algorithm (integrity.py).

The npm fixtures are real (openclaw@2026.11.3, fetched 2026-11-11): registry signature and Sigstore
provenance are verified offline against them. The full pipeline runs on a synthetic package.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sg_advance.integrity import (
    Manifest,
    dir_digest,
    effective_status,
    lookup,
    openclaw_components,
    tarball_components,
)
from sg_advance.server.supply import (
    SupplyError,
    parse_spec,
    publisher_for,
    sigstore_verifier,
    verify_npm_package,
    verify_registry_signature,
)

NPM = Path(__file__).parent / "fixtures" / "npm"
REAL_META = json.loads((NPM / "openclaw-2026.11.3.meta.json").read_text())
REAL_KEYS = json.loads((NPM / "keys.json").read_text())["keys"]
REAL_ATT = json.loads((NPM / "openclaw-2026.11.3.attestations.json").read_text())
REAL_DIST = REAL_META["versions"]["2026.11.3"]["dist"]
PUBLISHED = datetime.fromisoformat(REAL_META["time"]["2026.11.3"].replace("Z", "+00:00"))


# ── real npm data ────────────────────────────────────────────────────────────


def test_real_registry_signature_verifies() -> None:
    keyid = verify_registry_signature(
        "openclaw", "2026.11.3", REAL_DIST["integrity"], REAL_DIST["signatures"], REAL_KEYS, PUBLISHED
    )
    assert keyid.startswith("SHA256:")


def test_registry_signature_rejects_another_tarball_hash() -> None:
    forged = "sha512-" + base64.b64encode(hashlib.sha512(b"evil").digest()).decode()
    with pytest.raises(SupplyError, match="no valid npm registry signature"):
        verify_registry_signature(
            "openclaw", "2026.11.3", forged, REAL_DIST["signatures"], REAL_KEYS, PUBLISHED
        )


def _slsa_bundle() -> dict[str, Any]:
    return next(
        a for a in REAL_ATT["attestations"] if a["predicateType"] == "https://slsa.dev/provenance/v1"
    )["bundle"]


def test_real_provenance_verifies_for_the_publisher_repo() -> None:
    statement = sigstore_verifier(offline=True)(_slsa_bundle(), "openclaw/openclaw")
    assert statement["subject"][0]["name"] == "pkg:npm/openclaw@2026.11.3"


def test_real_provenance_rejects_another_repo() -> None:
    """A package built anywhere else (a fork, a typosquat's CI) must not pass as OpenClaw."""
    with pytest.raises(SupplyError, match="provenance does not verify"):
        sigstore_verifier(offline=True)(_slsa_bundle(), "someone/openclaw-fork")


def test_spec_and_publisher_rules() -> None:
    assert parse_spec("@openclaw/codex@2026.11.3") == ("@openclaw/codex", "2026.11.3")
    pubs = {"openclaw": "openclaw/openclaw", "@openclaw/": "openclaw/openclaw"}
    assert publisher_for("@openclaw/codex", pubs) == "openclaw/openclaw"
    with pytest.raises(SupplyError):
        publisher_for("openclaw-tools", pubs)  # a look-alike name gets no publisher


# ── synthetic package end to end ─────────────────────────────────────────────


def make_tarball(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, data in files.items():
            info = tarfile.TarInfo(f"package/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


FILES = {
    "package.json": b'{"name":"openclaw","version":"9.9.9"}',
    "dist/index.js": b"core()",
    "dist/extensions/ollama/index.js": b"ollama()",
    "dist/extensions/ollama/openclaw.plugin.json": b'{"id":"ollama"}',
    "dist/extensions/memory-core/index.js": b"memory()",
}


class FakeNpm:
    def __init__(
        self, tarball: bytes, *, sign_with: ec.EllipticCurvePrivateKey, version: str = "9.9.9"
    ) -> None:
        self.tarball = tarball
        self.integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        msg = f"openclaw@{version}:{self.integrity}".encode()
        sig = base64.b64encode(sign_with.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()
        der = sign_with.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.docs = {
            "https://r.test/openclaw": {
                "time": {version: "2026-11-01T00:00:00.000Z"},
                "versions": {
                    version: {
                        "dist": {
                            "integrity": self.integrity,
                            "tarball": "https://r.test/openclaw.tgz",
                            "signatures": [{"keyid": "k1", "sig": sig}],
                            "attestations": {"url": "https://r.test/att"},
                        }
                    }
                },
            },
            "https://r.test/-/npm/v1/keys": {
                "keys": [
                    {"keyid": "k1", "keytype": "ecdsa-sha2-nistp256", "key": base64.b64encode(der).decode()}
                ]
            },
            "https://r.test/att": {
                "attestations": [
                    {"predicateType": "https://slsa.dev/provenance/v1", "bundle": {"fake": True}}
                ]
            },
        }

    def json(self, url: str) -> Any:
        return self.docs[url]

    def bytes(self, url: str, limit: int = 0) -> bytes:
        return self.tarball


def fake_provenance(integrity: str, version: str = "9.9.9", repo_ok: str = "openclaw/openclaw"):
    def verify(bundle: dict[str, Any], repo: str) -> dict[str, Any]:
        if repo != repo_ok:
            raise SupplyError("provenance does not verify")
        digest = base64.b64decode(integrity.removeprefix("sha512-")).hex()
        return {"subject": [{"name": f"pkg:npm/openclaw@{version}", "digest": {"sha512": digest}}]}

    return verify


def test_pipeline_produces_components_matching_an_install(tmp_path: Path) -> None:
    tarball = make_tarball(FILES)
    npm = FakeNpm(tarball, sign_with=ec.generate_private_key(ec.SECP256R1()))
    pkg = verify_npm_package(
        "openclaw@9.9.9", fetcher=npm, provenance=fake_provenance(npm.integrity), registry="https://r.test"
    )
    assert set(pkg.components) == {"core", "plugin:ollama", "plugin:memory-core"}

    root = tmp_path / "openclaw"  # what `npm i -g` leaves on disk, plus its own dependencies
    for rel, data in FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    (root / "node_modules" / "dep").mkdir(parents=True)
    (root / "node_modules" / "dep" / "x.js").write_text("dep")
    assert openclaw_components(root) == pkg.components

    (root / "dist/extensions/ollama/index.js").write_bytes(b"ollama(); steal()")  # tampered on disk
    local = openclaw_components(root)
    assert local["plugin:ollama"] != pkg.components["plugin:ollama"]
    assert (
        local["core"] == pkg.components["core"]
        and local["plugin:memory-core"] == pkg.components["plugin:memory-core"]
    )
    (root / "dist/extensions/ollama/index.js").write_bytes(b"ollama()")
    (root / "dist/extensions/ollama/extra.js").write_text("added")  # an injected file counts too
    assert dir_digest(root / "dist/extensions/ollama") != pkg.components["plugin:ollama"]


def test_pipeline_rejects_tampered_tarball_and_foreign_provenance() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    npm = FakeNpm(make_tarball(FILES), sign_with=key)
    npm.tarball = make_tarball(FILES | {"dist/index.js": b"backdoor()"})  # mirror serves other bytes
    with pytest.raises(SupplyError, match="does not match its published integrity"):
        verify_npm_package(
            "openclaw@9.9.9",
            fetcher=npm,
            provenance=fake_provenance(npm.integrity),
            registry="https://r.test",
        )

    npm = FakeNpm(make_tarball(FILES), sign_with=key)
    with pytest.raises(SupplyError, match="provenance"):
        verify_npm_package(
            "openclaw@9.9.9",
            fetcher=npm,
            provenance=fake_provenance(npm.integrity, repo_ok="attacker/openclaw"),
            registry="https://r.test",
        )

    npm = FakeNpm(make_tarball(FILES), sign_with=key)
    npm.docs["https://r.test/-/npm/v1/keys"]["keys"][0]["key"] = base64.b64encode(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    with pytest.raises(SupplyError, match="registry signature"):
        verify_npm_package(
            "openclaw@9.9.9",
            fetcher=npm,
            provenance=fake_provenance(npm.integrity),
            registry="https://r.test",
        )


def test_plugin_package_layout_uses_manifest_id() -> None:
    tgz = make_tarball({"openclaw.plugin.json": b'{"id":"codex"}', "index.js": b"x"})
    assert list(tarball_components(tgz, "plugin")) == ["plugin:codex"]


# ── status and lookup ────────────────────────────────────────────────────────


def test_release_cooldown_then_trusted() -> None:
    pub = datetime(2026, 11, 10, 18, tzinfo=UTC)
    three = timedelta(days=3)
    assert effective_status(False, False, pub, three, now=pub + timedelta(hours=15)) == "cooling"
    assert effective_status(False, False, pub, three, now=pub + timedelta(days=3, minutes=1)) == "trusted"
    assert effective_status(True, False, pub, three, now=pub) == "approved"  # security approved early
    assert effective_status(True, True, pub, three, now=pub + timedelta(days=30)) == "revoked"


def test_lookup_prefers_the_best_status() -> None:
    ms = [
        Manifest(package="openclaw", version="1", status="cooling", components={"plugin:x": "d"}),
        Manifest(package="openclaw", version="2", status="approved", components={"plugin:x": "d"}),
    ]
    assert lookup(ms, "plugin:x", "d").version == "2"
    assert lookup(ms, "plugin:x", "other") is None

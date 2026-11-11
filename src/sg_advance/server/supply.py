"""Verify a published npm package and derive its known-good component digests (M5d).

For ``name@version`` the control plane checks, in order:

1. **Registry signature** — npm signs ``"<name>@<version>:<integrity>"`` with ECDSA P-256; the
   public keys come from ``/-/npm/v1/keys``. Proves the tarball hash is what npm published.
2. **Provenance** — the SLSA attestation is a Sigstore bundle. Its Fulcio certificate must come from
   GitHub Actions in the trusted repository (``openclaw/openclaw``), the transparency log entry must
   verify, and its subject digest must equal the tarball hash. Proves who built it, from what source.
3. **Tarball** — download it and check sha512 against ``integrity``.

Only then are digests computed (``integrity.tarball_components``). The sensor compares installed
files with them, so a bundled plugin edited on disk no longer matches anything the publisher signed.

Whether a verified release is *trusted* also depends on age (release cooldown, default 3 days): most
malicious npm releases are caught and pulled within days. Security can approve earlier by hand.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..integrity import tarball_components

NPM_REGISTRY = "https://registry.npmjs.org"
SLSA_V1 = "https://slsa.dev/provenance/v1"
GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
MAX_TARBALL = 400 * 1024 * 1024
# Which repository may build which packages. Prefix match on the npm name ("@openclaw/" = scope).
DEFAULT_PUBLISHERS = {"openclaw": "openclaw/openclaw", "@openclaw/": "openclaw/openclaw"}


class SupplyError(Exception):
    """The package could not be verified; nothing about it is trusted."""


class Fetcher(Protocol):
    def json(self, url: str) -> Any: ...
    def bytes(self, url: str, limit: int = MAX_TARBALL) -> bytes: ...


class HttpFetcher:
    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout

    def _open(self, url: str) -> Any:
        if not url.startswith("https://"):
            raise SupplyError(f"refusing non-https url: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "sg-advance-control-plane"})
        return urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310 - https enforced above

    def json(self, url: str) -> Any:
        with self._open(url) as r:
            return json.loads(r.read())

    def bytes(self, url: str, limit: int = MAX_TARBALL) -> bytes:
        with self._open(url) as r:
            data = r.read(limit + 1)
        if len(data) > limit:
            raise SupplyError(f"tarball larger than {limit} bytes")
        return data


class ProvenanceVerifier(Protocol):
    def __call__(self, bundle: dict[str, Any], repo: str) -> dict[str, Any]:
        """Verify a Sigstore bundle for ``repo``; return the in-toto statement."""
        ...


def sigstore_verifier(offline: bool = False) -> ProvenanceVerifier:
    """Real verification with sigstore-python (server extra). ``offline`` uses the embedded trust
    root instead of refreshing it over TUF (tests, air-gapped servers)."""
    from sigstore.models import Bundle, ClientTrustConfig
    from sigstore.verify import Verifier
    from sigstore.verify.policy import AllOf, GitHubWorkflowRepository, OIDCIssuer

    verifier = Verifier(trusted_root=ClientTrustConfig.production(offline=offline).trusted_root)

    def verify(bundle: dict[str, Any], repo: str) -> dict[str, Any]:
        policy = AllOf([OIDCIssuer(GITHUB_ACTIONS_ISSUER), GitHubWorkflowRepository(repo)])
        try:
            ptype, payload = verifier.verify_dsse(Bundle.from_json(json.dumps(bundle)), policy)
        except Exception as e:  # sigstore raises several types; all mean "not verified"
            raise SupplyError(f"provenance does not verify for {repo}: {e}") from e
        if ptype != "application/vnd.in-toto+json":
            raise SupplyError(f"unexpected provenance payload type {ptype}")
        return json.loads(payload)

    return verify


@dataclass
class VerifiedPackage:
    package: str
    version: str
    integrity: str
    published_at: datetime
    source_repo: str
    components: dict[str, str]
    notes: list[str] = field(default_factory=list)


def parse_spec(spec: str) -> tuple[str, str]:
    """``openclaw@2026.11.3`` / ``@openclaw/codex@2026.11.3`` → (name, version)."""
    name, sep, version = spec.rpartition("@")
    if not sep or not name or not version:
        raise SupplyError(f"expected name@version, got {spec!r}")
    return name, version


def publisher_for(name: str, publishers: dict[str, str]) -> str:
    for prefix, repo in publishers.items():
        if name == prefix or (prefix.endswith("/") and name.startswith(prefix)):
            return repo
    raise SupplyError(f"no trusted publisher configured for {name}")


def _sri_hex(integrity: str) -> str:
    algo, _, b64 = integrity.partition("-")
    if algo != "sha512":
        raise SupplyError(f"unsupported integrity algorithm {algo}")
    return base64.b64decode(b64).hex()


def verify_registry_signature(
    name: str,
    version: str,
    integrity: str,
    signatures: list[dict[str, Any]],
    keys: list[dict[str, Any]],
    published: datetime,
) -> str:
    """Return the key id that signed it. Keys that had expired before publication don't count."""
    message = f"{name}@{version}:{integrity}".encode()
    by_id = {k["keyid"]: k for k in keys}
    for sig in signatures:
        key = by_id.get(sig.get("keyid"))
        if key is None or key.get("keytype") != "ecdsa-sha2-nistp256":
            continue
        expires = key.get("expires")
        if expires and datetime.fromisoformat(expires.replace("Z", "+00:00")) < published:
            continue
        pub = serialization.load_der_public_key(base64.b64decode(key["key"]))
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            continue
        try:
            pub.verify(base64.b64decode(sig["sig"]), message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            continue
        return key["keyid"]
    raise SupplyError(f"no valid npm registry signature for {name}@{version}")


def _check_statement(statement: dict[str, Any], name: str, version: str, integrity: str) -> None:
    want = f"pkg:npm/{urllib.parse.quote(name, safe='/')}@{version}"
    for subject in statement.get("subject", []):
        if subject.get("name") == want and subject.get("digest", {}).get("sha512") == _sri_hex(integrity):
            return
    raise SupplyError(f"provenance subject does not match {want} and its tarball hash")


def verify_npm_package(
    spec: str,
    *,
    fetcher: Fetcher,
    provenance: ProvenanceVerifier,
    publishers: dict[str, str] | None = None,
    registry: str = NPM_REGISTRY,
) -> VerifiedPackage:
    name, version = parse_spec(spec)
    repo = publisher_for(name, publishers or DEFAULT_PUBLISHERS)
    doc = fetcher.json(f"{registry}/{urllib.parse.quote(name, safe='@')}")
    meta = (doc.get("versions") or {}).get(version)
    if meta is None:
        raise SupplyError(f"{spec} is not published")
    dist = meta["dist"]
    integrity = dist["integrity"]
    published = datetime.fromisoformat(doc["time"][version].replace("Z", "+00:00"))

    keys = fetcher.json(f"{registry}/-/npm/v1/keys")["keys"]
    keyid = verify_registry_signature(name, version, integrity, dist.get("signatures") or [], keys, published)

    att_url = (dist.get("attestations") or {}).get("url")
    if not att_url:
        raise SupplyError(f"{spec} has no provenance attestation")
    attestations = fetcher.json(att_url)["attestations"]
    slsa = next((a for a in attestations if a.get("predicateType") == SLSA_V1), None)
    if slsa is None:
        raise SupplyError(f"{spec} has no SLSA provenance")
    _check_statement(provenance(slsa["bundle"], repo), name, version, integrity)

    tarball = fetcher.bytes(dist["tarball"])
    got = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    if got != integrity:
        raise SupplyError(f"{spec} tarball does not match its published integrity")
    layout = "openclaw" if name == "openclaw" else "plugin"
    return VerifiedPackage(
        package=name,
        version=version,
        integrity=integrity,
        published_at=published,
        source_repo=repo,
        components=tarball_components(tarball, layout),
        notes=[f"registry key {keyid}", f"provenance {repo}"],
    )

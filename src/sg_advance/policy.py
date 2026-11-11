"""Policy bundle: what the control plane hands to sensors.

v0 (M3) is every rule under ``rules/`` plus a content hash (``version``). Sensors compare the
hash to decide whether to rebuild their engine. M9 adds versions, target groups and response
overrides on top of the same envelope.

Since M4 the server signs ``version`` with Ed25519. Because ``version`` is the sha256 of the
rules, checking the hash *and* the signature proves the rules came from the server unchanged,
both on the wire and in the sensor's on-disk cache.

This module has no server dependencies so endpoint sensors can import it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from .detect.rules import Rule, RuleSet

# Domain separation: a signature over a policy version can't be replayed as anything else.
_SIGNING_CONTEXT = b"sg-advance/policy-bundle/v1:"


class PolicyVerificationError(ValueError):
    pass


def _digest(rules: list[dict[str, Any]], manifests: list[dict[str, Any]] | None = None) -> str:
    """Rules only (as before) when there are no manifests, so older bundles keep their version."""
    doc: Any = {"manifests": manifests, "rules": rules} if manifests else rules
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── keys ────────────────────────────────────────────────────────────────────


def public_key_b64(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def load_public_key(b64: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64, validate=True))
    except ValueError as e:
        raise PolicyVerificationError(f"invalid policy public key: {e}") from e


def key_id(key: Ed25519PublicKey | str) -> str:
    """Short fingerprint people can compare by eye (first 16 hex of sha256 of the raw key)."""
    b64 = key if isinstance(key, str) else public_key_b64(key)
    return hashlib.sha256(base64.b64decode(b64)).hexdigest()[:16]


def load_or_create_signing_key(path: Path) -> Ed25519PrivateKey:
    """Server side. Creates the key on first start; file is readable by the owner only."""
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path.touch(mode=0o600)
    path.write_bytes(pem)
    return key


# ── bundle ──────────────────────────────────────────────────────────────────


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle_format: Literal["1"] = "1"
    version: str = Field(description="sha256 of the canonical rules (+ manifests); signed")
    rules: tuple[dict[str, Any], ...] = Field(description="Rule documents (rules/*.yaml entries as JSON)")
    manifests: tuple[dict[str, Any], ...] = Field(
        default=(), description="Known-good package digests (integrity.Manifest), covered by version"
    )
    key_id: str | None = Field(default=None, description="Fingerprint of the signing key")
    signature: str | None = Field(default=None, description="base64 Ed25519 signature over version")

    @classmethod
    def from_ruleset(cls, ruleset: RuleSet, manifests: list[dict[str, Any]] | None = None) -> PolicyBundle:
        docs = [r.model_dump(mode="json") for r in ruleset.rules]
        mans = list(manifests or [])
        return cls(version=_digest(docs, mans), rules=tuple(docs), manifests=tuple(mans))

    @classmethod
    def load(cls, rules_dir: Path, manifests: list[dict[str, Any]] | None = None) -> PolicyBundle:
        return cls.from_ruleset(RuleSet.load(rules_dir), manifests)

    def signed(self, key: Ed25519PrivateKey) -> PolicyBundle:
        sig = key.sign(_SIGNING_CONTEXT + self.version.encode("ascii"))
        return self.model_copy(
            update={"key_id": key_id(key.public_key()), "signature": base64.b64encode(sig).decode("ascii")}
        )

    def _check_digest(self) -> list[dict[str, Any]]:
        docs = [dict(r) for r in self.rules]
        if _digest(docs, [dict(m) for m in self.manifests]) != self.version:
            raise PolicyVerificationError("policy bundle hash mismatch")
        return docs

    def verify(self, public_key: Ed25519PublicKey) -> None:
        """Raise unless the rules hash to ``version`` and ``version`` carries a valid signature."""
        self._check_digest()
        if self.signature is None:
            raise PolicyVerificationError("policy bundle is not signed")
        try:
            sig = base64.b64decode(self.signature, validate=True)
            public_key.verify(sig, _SIGNING_CONTEXT + self.version.encode("ascii"))
        except (ValueError, InvalidSignature) as e:
            raise PolicyVerificationError("policy bundle signature is invalid") from e

    def to_ruleset(self, public_key: Ed25519PublicKey | None = None) -> RuleSet:
        """Rebuild the engine's rule set. Sensors pass the server key so unsigned or forged
        bundles are rejected; without a key only the content hash is checked."""
        if public_key is not None:
            self.verify(public_key)
        docs = self._check_digest()
        return RuleSet([Rule.model_validate(d) for d in docs], {d["id"]: "policy" for d in docs})

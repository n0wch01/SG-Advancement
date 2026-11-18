"""Purpose-separated, signed task capabilities. Signature validity alone is not authorization."""

from __future__ import annotations

import base64
import json
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .policy import key_id

CONTEXT = b"SG-Advance task grant v1\x00"
MAX_TOKEN_BYTES = 16384
# What a task grant can carry (2026-11-18: + PR and CI at the Git gateway). Production deployment stays
# out: no task grant can carry it, so deploy refs and tags are refused for every agent in this stage.
SUPPORTED_ACTIONS = frozenset({"source.read", "source.write", "tests.write", "pr.create", "ci.run"})
AGENT_PROFILES = {
    "reader": frozenset({"source.read"}),
    "tester": frozenset({"source.read", "tests.write", "ci.run"}),
    "coder": SUPPORTED_ACTIONS,
}


class GrantError(ValueError):
    pass


def relative_path(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(p in {"", ".", ".."} for p in value.rstrip("/").split("/"))
    ):
        raise GrantError("a canonical relative path is required")
    return value.rstrip("/")


def within(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


class TaskClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: Literal["sg-advance.task"] = "sg-advance.task"
    version: Literal[1] = 1
    grant_id: str = Field(min_length=1, max_length=64)
    user_id: str = Field(min_length=1, max_length=100)
    device_id: str = Field(min_length=1, max_length=100)
    binding_id: str = Field(min_length=1, max_length=64)
    agent_type: Literal["claude_code", "codex_cli"]
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    project_id: str = Field(min_length=1, max_length=100)
    environment: Literal["development", "test"]
    agent_profile: Literal["reader", "tester", "coder"]
    actions: tuple[str, ...] = Field(min_length=1, max_length=5)
    paths: tuple[str, ...] = Field(min_length=1, max_length=16)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    policy_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    parent_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def valid_scope(self) -> TaskClaims:
        if self.expires_at <= self.issued_at or not set(self.actions) <= AGENT_PROFILES[self.agent_profile]:
            raise ValueError("invalid task lifetime or agent profile scope")
        if len(set(self.actions)) != len(self.actions) or len(set(self.paths)) != len(self.paths):
            raise ValueError("duplicate task scope")
        if any(len(p) > 256 or relative_path(p) != p for p in self.paths):
            raise ValueError("invalid task resource path")
        return self


def canonical(claims: TaskClaims) -> bytes:
    return json.dumps(claims.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()


def sign_task(claims: TaskClaims, key: Ed25519PrivateKey) -> str:
    doc = {
        "claims": claims.model_dump(mode="json"),
        "key_id": key_id(key.public_key()),
        "signature": base64.b64encode(key.sign(CONTEXT + canonical(claims))).decode(),
    }
    return base64.urlsafe_b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()


def verify_task(token: str, key: Ed25519PublicKey) -> TaskClaims:
    try:
        if len(token) > MAX_TOKEN_BYTES:
            raise GrantError("oversized task token")
        raw = base64.b64decode(token.encode("ascii"), altchars=b"-_", validate=True)
        doc = json.loads(raw)
        if set(doc) != {"claims", "key_id", "signature"} or doc["key_id"] != key_id(key):
            raise GrantError("invalid task envelope")
        claims = TaskClaims.model_validate(doc["claims"])
        key.verify(base64.b64decode(doc["signature"], validate=True), CONTEXT + canonical(claims))
        return claims
    except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError) as exc:
        raise GrantError("invalid task grant") from exc

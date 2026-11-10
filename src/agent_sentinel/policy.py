"""Policy bundle: what the control plane hands to sensors.

v0 (M3) is simply every rule under ``rules/`` plus a content hash. Sensors compare the hash to
decide whether to rebuild their engine. M9 adds versions, target groups and response overrides
on top of the same envelope.

This module has no server dependencies so endpoint sensors can import it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .detect.rules import Rule, RuleSet


def _digest(rules: list[dict[str, Any]]) -> str:
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle_format: Literal["1"] = "1"
    version: str = Field(description="sha256 of the canonical rule list; changes iff rules change")
    rules: tuple[dict[str, Any], ...] = Field(description="Rule documents (rules/*.yaml entries as JSON)")

    @classmethod
    def from_ruleset(cls, ruleset: RuleSet) -> PolicyBundle:
        docs = [r.model_dump(mode="json") for r in ruleset.rules]
        return cls(version=_digest(docs), rules=tuple(docs))

    @classmethod
    def load(cls, rules_dir: Path) -> PolicyBundle:
        return cls.from_ruleset(RuleSet.load(rules_dir))

    def to_ruleset(self) -> RuleSet:
        """Rebuild the engine's rule set on the sensor side. Raises if the bundle was tampered with."""
        docs = [dict(r) for r in self.rules]
        if _digest(docs) != self.version:
            raise ValueError("policy bundle hash mismatch")
        return RuleSet([Rule.model_validate(d) for d in docs], {d["id"]: "policy" for d in docs})

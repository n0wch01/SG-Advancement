"""Declarative detection rules (rules/*.yaml) and their loader.

Rules only ever address fields of the AgentEvent JSON form via dotted paths, e.g.
``payload.kind``, ``payload.arguments``, ``payload.tools[].description``, ``principal.user_id``.
See docs/detection.md for the format and the tuning workflow.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..schema import ResponseAction, Severity, ThreatCategory

DEFAULT_GROUP_BY = ("endpoint.device_id", "agent.session_id", "payload.tool")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Condition = dict[str, tuple[str, ...]]


def _coerce_condition(v: object) -> object:
    """Allow ``{path: value}`` as shorthand for ``{path: [value]}``."""
    if isinstance(v, dict):
        return {k: (x,) if isinstance(x, str) else x for k, x in v.items()}
    return v


@lru_cache(maxsize=1024)
def compile_pattern(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE if ignore_case else 0)


class _PatternMixin(_Model):
    pattern: str | None = None
    ignore_case: bool = False
    fields: tuple[str, ...] = Field(
        default=("payload",), description="Paths whose string leaves are searched"
    )

    @field_validator("pattern")
    @classmethod
    def _valid_regex(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"invalid regex {v!r}: {e}") from e
        return v

    def compiled(self) -> re.Pattern[str] | None:
        return compile_pattern(self.pattern, self.ignore_case) if self.pattern is not None else None


class RegexMatch(_PatternMixin):
    """Fires when ``pattern`` is found in any string under ``fields``."""

    type: Literal["regex"]
    pattern: str


class AllowlistMatch(_Model):
    """Fires when a value at ``field`` is not covered by ``allow`` (fnmatch globs, e.g. ``*.corp``).
    Missing / null values are ignored."""

    type: Literal["allowlist"]
    field: str
    allow: tuple[str, ...] = ()
    ignore_case: bool = True
    allow_trusted: str | None = Field(
        default=None,
        description="Also allow values in this sensor-maintained trusted set (e.g. openclaw_plugins: "
        "plugins whose installed code matches a signed, approved package). Empty outside a sensor.",
    )


class InSetMatch(_Model):
    """Fires when a value at one of ``fields`` is in a sensor-maintained set named ``set``: e.g. the
    conversations or people security blocked remotely (M11). Empty outside a sensor, so it never
    fires in plain replays."""

    type: Literal["in_set"]
    set: str = Field(min_length=1)
    fields: tuple[str, ...] = Field(min_length=1)


class RateMatch(_Model):
    """Fires once ``threshold`` matching events occur within ``window_seconds`` for one group."""

    type: Literal["rate"]
    window_seconds: float = Field(gt=0)
    threshold: int = Field(ge=1)
    group_by: tuple[str, ...] = DEFAULT_GROUP_BY


class RepeatMatch(_Model):
    """Fires when ``threshold`` consecutive events of one group have identical ``same`` values."""

    type: Literal["repeat"]
    threshold: int = Field(ge=2)
    group_by: tuple[str, ...] = DEFAULT_GROUP_BY
    same: tuple[str, ...] = ("payload.tool", "payload.arguments")


class SequenceStep(_PatternMixin):
    name: str | None = None
    when: Condition = Field(default_factory=dict)

    @field_validator("when", mode="before")
    @classmethod
    def _coerce_when(cls, v: object) -> object:
        return _coerce_condition(v)


class SequenceMatch(_Model):
    """Fires when the steps happen in order inside one session (or one delegation tree), all within
    ``within_seconds``."""

    type: Literal["sequence"]
    steps: tuple[SequenceStep, ...] = Field(min_length=2)
    within_seconds: float = Field(default=600, gt=0)
    scope: Literal["session", "delegation"] = Field(
        default="session",
        description="delegation = a session and the sub-agent sessions it spawned (agent.root_session_id)",
    )
    distinct_sessions: bool = Field(
        default=False, description="The last step must happen in a different session than the first"
    )


Match = Annotated[
    RegexMatch | AllowlistMatch | InSetMatch | RateMatch | RepeatMatch | SequenceMatch,
    Field(discriminator="type"),
]


class Rule(_Model):
    id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    version: str = "1"
    enabled: bool = True
    severity: Severity
    category: ThreatCategory
    title: str
    message: str = ""
    recommended_action: str = ""
    response: ResponseAction = Field(
        default=ResponseAction.ALERT,
        description="Suggested response; M2 only records it (enforced=false)",
    )
    confidence: float = Field(default=1.0, ge=0, le=1)
    tags: tuple[str, ...] = ()
    dedup: Literal["session", "none"] = Field(
        default="session",
        description="session = one finding per rule/session/key; the verdict still applies every time",
    )
    when: Condition = Field(default_factory=dict, description="Pre-filter: every path must hold one value")
    unless: Condition = Field(
        default_factory=dict, description="Exception: skip the event when every path holds one value"
    )
    match: Match

    @field_validator("when", "unless", mode="before")
    @classmethod
    def _coerce_when(cls, v: object) -> object:
        return _coerce_condition(v)


class RuleFile(_Model):
    version: Literal[1]
    rules: tuple[Rule, ...] = ()


class RuleLoadError(ValueError):
    pass


class RuleSet:
    def __init__(self, rules: list[Rule], sources: dict[str, str] | None = None) -> None:
        seen: dict[str, str] = {}
        for r in rules:
            src = (sources or {}).get(r.id, "?")
            if r.id in seen:
                raise RuleLoadError(f"duplicate rule id {r.id!r} ({seen[r.id]} and {src})")
            seen[r.id] = src
        self.rules = rules
        self.sources = sources or {}

    @property
    def enabled(self) -> list[Rule]:
        return [r for r in self.rules if r.enabled]

    def get(self, rule_id: str) -> Rule:
        for r in self.rules:
            if r.id == rule_id:
                return r
        raise KeyError(rule_id)

    @classmethod
    def load(cls, path: Path) -> RuleSet:
        files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
        if not files:
            raise RuleLoadError(f"no rule files under {path}")
        rules: list[Rule] = []
        sources: dict[str, str] = {}
        for f in files:
            try:
                parsed = RuleFile.model_validate(yaml.safe_load(f.read_text(encoding="utf-8")) or {})
            except (yaml.YAMLError, ValidationError) as e:
                raise RuleLoadError(f"{f}: {e}") from e
            for r in parsed.rules:
                if r.id in sources:
                    raise RuleLoadError(f"duplicate rule id {r.id!r} ({sources[r.id]} and {f.name})")
                sources[r.id] = f.name
                rules.append(r)
        return cls(rules, sources)

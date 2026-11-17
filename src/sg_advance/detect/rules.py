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
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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


class NumberMatch(_Model):
    """Fires when a number under ``fields`` falls inside the bounds (2026-11-16: thresholds belong in the
    signed policy, not in code). Strings that read as numbers count (labels are strings, e.g.
    ``labels.sga_judge_score: "0.970"``); anything else under the field is ignored. At least one bound."""

    type: Literal["number"]
    fields: tuple[str, ...] = Field(min_length=1)
    at_least: float | None = None
    above: float | None = None
    at_most: float | None = None
    below: float | None = None

    @model_validator(mode="after")
    def _one_bound(self) -> NumberMatch:
        if all(b is None for b in (self.at_least, self.above, self.at_most, self.below)):
            raise ValueError("number match needs at least one of at_least, above, at_most, below")
        return self

    def holds(self, x: float) -> bool:
        return (
            (self.at_least is None or x >= self.at_least)
            and (self.above is None or x > self.above)
            and (self.at_most is None or x <= self.at_most)
            and (self.below is None or x < self.below)
        )

    def bounds(self) -> str:
        parts = [(self.at_least, "≥"), (self.above, ">"), (self.at_most, "≤"), (self.below, "<")]
        return " and ".join(f"{op} {v:g}" for v, op in parts if v is not None)


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
    RegexMatch | AllowlistMatch | InSetMatch | NumberMatch | RateMatch | RepeatMatch | SequenceMatch,
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

    @field_validator("response", mode="before")
    @classmethod
    def _no_security_hold(cls, v: object) -> object:
        """The security team's pre-approval hold was removed (2026-11-17). A rule that still asks for it
        (an old cached policy, an old rules file) is a deny: stricter, never looser (fail closed)."""
        legacy = v in ("security_approval", ResponseAction.SECURITY_APPROVAL)
        return ResponseAction.BLOCK.value if legacy else v


class RuleFile(_Model):
    version: Literal[1]
    rules: tuple[Rule, ...] = ()


class RuleLoadError(ValueError):
    pass


# First stage of the rule → classifier cascade (docs/classifier.md): a rule tagged ``stage:candidate`` only
# marks events for the sensor's classifier. It never enforces and never makes a finding: the enforcement
# engine leaves it out (Engine(stage="enforce"), the default). A tag, not a field, so older sensors still
# load the policy; they would run it as an ordinary rule, which is why a candidate rule must be harmless
# there: response ``allow`` and severity ``info`` (checked here).
CANDIDATE_TAG = "stage:candidate"


def is_candidate(rule: Rule) -> bool:
    return CANDIDATE_TAG in rule.tags


class RuleSet:
    def __init__(self, rules: list[Rule], sources: dict[str, str] | None = None) -> None:
        seen: dict[str, str] = {}
        for r in rules:
            src = (sources or {}).get(r.id, "?")
            if r.id in seen:
                raise RuleLoadError(f"duplicate rule id {r.id!r} ({seen[r.id]} and {src})")
            seen[r.id] = src
            harmless = r.response is ResponseAction.ALLOW and r.severity is Severity.INFO
            if is_candidate(r) and not harmless:
                raise RuleLoadError(
                    f"candidate rule {r.id!r} ({src}) must have response allow and severity info: "
                    "older sensors run it as an ordinary rule"
                )
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

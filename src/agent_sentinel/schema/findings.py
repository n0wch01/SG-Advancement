"""Finding: a detection result, plus what was done about it."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field

from .common import SCHEMA_VERSION, AgentRef, Endpoint, Principal, SensorType, StrictModel
from .events import AgentEvent, new_id


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity | str) -> bool:
        return self.rank >= Severity(other).rank


_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


class ThreatCategory(StrEnum):
    """Coarse category shown in the console. Fine-grained framework ids
    (OWASP LLM / Agentic, MITRE ATLAS) go into Finding.tags."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SUPPLY_CHAIN = "supply_chain"
    TOOL_MISUSE = "tool_misuse"
    RESOURCE_ABUSE = "resource_abuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_POISONING = "memory_poisoning"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class ResponseAction(StrEnum):
    """Ordered from least to most disruptive."""

    ALLOW = "allow"
    ALERT = "alert"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"  # deny this single tool call / request
    ABORT_SESSION = "abort_session"  # stop the whole agent run
    QUARANTINE = "quarantine"  # disable plugin / MCP server on the endpoint


class Enforcement(StrictModel):
    action: ResponseAction
    enforced: bool = Field(description="False = recommended only (detect mode) or enforcement failed")
    enforcer: SensorType | Literal["control_plane"]
    detail: str | None = None


class Finding(StrictModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    finding_id: str = Field(default_factory=new_id)
    ts: AwareDatetime
    rule_id: str = Field(min_length=1)
    rule_version: str | None = None
    severity: Severity
    category: ThreatCategory
    title: str
    message: str = ""
    recommended_action: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detector: Literal["local", "central"] = "local"
    evidence_event_ids: tuple[str, ...] = ()
    endpoint: Endpoint
    principal: Principal
    agent: AgentRef
    response: Enforcement | None = None
    tags: tuple[str, ...] = Field(default=(), description="e.g. owasp-llm:LLM01, mitre-atlas:AML.T0051")
    labels: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_event(
        cls,
        event: AgentEvent,
        *,
        rule_id: str,
        severity: Severity | str,
        category: ThreatCategory | str,
        title: str,
        ts: AwareDatetime | None = None,
        **kwargs,
    ) -> Finding:
        """Build a finding that inherits who/where/which-agent context from its trigger event."""
        evidence = kwargs.pop("evidence_event_ids", (event.event_id,))
        return cls(
            ts=ts or event.ts,
            rule_id=rule_id,
            severity=Severity(severity),
            category=ThreatCategory(category),
            title=title,
            evidence_event_ids=tuple(evidence),
            endpoint=event.endpoint,
            principal=event.principal,
            agent=event.agent,
            labels=dict(event.labels) | kwargs.pop("labels", {}),
            **kwargs,
        )

"""Every ``labels.sga_*`` name, declared once, with who may set it (2026-11-18, docs/detection.md).

Labels carry verified state into the signed rules (CLAUDE.md conventions). A label is only as good as its
writer, so each one names its source, and the stripping and checks are derived from that:

- ``sensor``: computed by ``Sensor.stamp`` (or a module it calls). The same name arriving with an event is
  dropped before stamping and recomputed (``core.Sensor._OWN_LABELS``).
- ``decision``: written by the daemon's decision code on events it builds itself (approval audit). Dropped
  from events that arrive over the local API (``decision.judge_event``).
- ``enforcement_point``: written by the hook / plugin / gateway from its own verified context (the agent's
  tool input never sets labels). Same-user processes can reach the local API, so these are trusted as
  much as that boundary: never a reason to relax a decision by themselves.
- ``control_plane``: written by the server (registered identity, task grants). Dropped from anything a
  client sends (``server.access.collection_identity``).
- ``finding``: on findings, not events (enforced repeats).

``tests/test_labels.py`` holds the code and the rules to this list: an unregistered name written in the
code, or read by a rule, fails CI (a misspelt label in a rule would otherwise never match, silently).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Source = Literal["sensor", "decision", "enforcement_point", "control_plane", "finding"]


@dataclass(frozen=True)
class Label:
    source: Source
    description: str


LABELS: dict[str, Label] = {
    # ── sensor: stamped, never taken from input ──
    "sga_input_source": Label("sensor", "where a tool result came from (host, mcp:<server>, local, unknown)"),
    "sga_result_origin": Label(
        "sensor", "verified origin: protected_resource, its control_plane_denial, or the sensor_notice"
    ),
    "sga_data_class": Label("sensor", "lineage: protected data in this call's arguments"),
    "sga_lineage": Label("sensor", "lineage tracking state (tracked, unavailable)"),
    "sga_lineage_sources": Label("sensor", "lineage: source event ids of the protected values"),
    "sga_lineage_fields": Label("sensor", "lineage: protected column names"),
    "sga_lineage_via": Label("sensor", "lineage: how the value was linked (value, file)"),
    "sga_destinations": Label("sensor", "where a call sends its arguments (comma list)"),
    "sga_runs_downloaded": Label("sensor", "the call runs a file downloaded earlier: '<host> <path>'"),
    "sga_delegation_escalation": Label("sensor", "a child agent gets more permission than its parent"),
    "sga_delegation_def": Label("sensor", "the subagent definition the call delegates to"),
    "sga_delegation_child": Label("sensor", "the child agent's mode/sandbox, for the delegation rules"),
    "sga_candidate": Label("sensor", "candidate rules that sent this result to the classifier"),
    "sga_judge_injection": Label("sensor", "classifier verdict: malicious, unsure, benign, unavailable"),
    "sga_judge_score": Label("sensor", "classifier worst chunk score (not a probability)"),
    "sga_judge_model": Label("sensor", "classifier model and revision"),
    "sga_judge_chunks": Label("sensor", "chunks scanned / total"),
    "sga_judge_reason": Label("sensor", "why the scan stopped or failed"),
    "sga_act_parse": Label("sensor", "action normaliser: ok, partial, unsupported"),
    "sga_act_unknown": Label("sensor", "what the normaliser could not read, and why"),
    "sga_act_ops": Label("sensor", "operations found: delete, write, exec, read"),
    "sga_act_destroy": Label("sensor", "destructive kinds found (actions.KINDS)"),
    "sga_act_targets": Label("sensor", "targets of those operations, as written"),
    "sga_posture": Label("sensor", "device posture: ok, degraded, unknown"),
    "sga_posture_reasons": Label("sensor", "why the posture is not ok"),
    "sga_policy_stale": Label("sensor", "the signed policy is older than its allowed age"),
    "sga_policy_age_hours": Label("sensor", "age of the signed policy"),
    "sga_enforcement_contradicted": Label("sensor", "a result arrived for a call this sensor refused"),
    "sga_contradicted_findings": Label("sensor", "findings whose refusal the result contradicts"),
    # ── decision: the daemon's approval audit ──
    "sga_approval_inferred": Label("decision", "approval answer inferred from: tool_result, no_result"),
    "sga_approval_mismatch": Label("decision", "what ran is not what the person approved"),
    # ── enforcement points: from their own context ──
    "sga_source": Label("enforcement_point", "which enforcement point built the event"),
    "sga_input_digest": Label("enforcement_point", "fingerprint of the tool input (approval binding)"),
    "sga_attended": Label("enforcement_point", "a person is at the session (hook environment)"),
    "sga_permission_mode": Label("enforcement_point", "the agent's permission mode (default, bypass, …)"),
    "sga_result_uninspected": Label("enforcement_point", "the result was too large to inspect"),
    "sga_verdict": Label("enforcement_point", "judged without the daemon: degraded"),
    "sga_plugin": Label("enforcement_point", "OpenClaw WS adapter: the gateway plugin never saw the call"),
    "sga_client_device": Label("enforcement_point", "MCP gateway: the calling device (LAN gateway mTLS)"),
    # ── control plane: never from a client ──
    "sga_project_id": Label("control_plane", "registered project of the session"),
    "sga_verified_user": Label("control_plane", "registered person of the session"),
    "sga_identity_source": Label("control_plane", "registered_session or unverified"),
    "sga_task_grant_id": Label("control_plane", "task grant used at the resource gateway"),
    "sga_authorization": Label("control_plane", "resource gateway authorization: allow, deny"),
    # ── findings ──
    "sga_repeat": Label("finding", "an enforced call's finding that dedup would have suppressed"),
}


def from_source(source: Source) -> frozenset[str]:
    return frozenset(name for name, label in LABELS.items() if label.source == source)


SENSOR_OWNED = from_source("sensor")
DECISION_OWNED = from_source("decision")
CONTROL_PLANE_OWNED = from_source("control_plane")


_REFERENCE = re.compile(r"labels\.(sga_[a-z0-9_]+)")


def referenced(value: object) -> set[str]:
    """``sga_*`` label names a rule (or any nested document) reads: keys, values and tag texts alike."""
    found: set[str] = set()
    if isinstance(value, str):
        found.update(_REFERENCE.findall(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            found |= referenced(k) | referenced(v)
    elif isinstance(value, list | tuple | set | frozenset):
        for v in value:
            found |= referenced(v)
    return found


def unknown_in_rules(rules: list[dict]) -> dict[str, set[str]]:
    """Rule id → the unregistered ``sga_*`` labels it reads (a typo would never match, silently)."""
    out = {}
    for rule in rules:
        missing = referenced(rule) - LABELS.keys()
        if missing:
            out[str(rule.get("id"))] = missing
    return out

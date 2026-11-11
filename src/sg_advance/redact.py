"""Secret redaction applied on the endpoint before events or findings leave it.

Detection runs on the original event (so credential-leak rules can see the secret); this module
is applied afterwards, right before anything is shipped to the control plane, and to every
excerpt a finding quotes.
"""

from __future__ import annotations

import re
from typing import Any

from .schema import AgentEvent

# (label, pattern, keep_prefix_group). When keep_prefix_group is True, group 1 (e.g. "api_key=")
# is kept so the redacted text still shows *what kind* of value was there.
_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
            r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
        False,
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"), False),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), False),
    ("api-key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"), False),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), False),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), False),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    ("bearer", re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{20,}"), True),
    (
        "secret",
        re.compile(
            r"(?i)(\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|password|passwd|pwd)"
            r"[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED)[^\s\"'&,;]{4,}"
        ),
        True,
    ),
]


def redact_text(text: str) -> str:
    for label, pat, keep_prefix in _PATTERNS:
        placeholder = f"[REDACTED:{label}]"
        if keep_prefix:
            text = pat.sub(lambda m, p=placeholder: m.group(1) + p, text)
        else:
            text = pat.sub(placeholder, text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively redact every string inside dicts / lists."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(v) for v in value]
    return value


def redact_event(event: AgentEvent) -> AgentEvent:
    """Return a copy of the event with secrets masked in payload and raw frame."""
    doc = event.model_dump(mode="json")
    doc["payload"] = redact_value(doc["payload"])
    if doc.get("raw") is not None:
        doc["raw"] = redact_value(doc["raw"])
    return AgentEvent.model_validate(doc)

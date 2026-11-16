"""The AgentEvent v1 envelope every sensor fills the same way, in one place (refactor 2026-11-15:
eleven adapters built it by hand).

Standard library only: ``sga-hook`` imports it and must stay light (it starts once per tool call).
The device id is ``pending`` here; the sensor core stamps the real one when the event is spooled.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def envelope(
    *,
    sensor: str,
    agent: dict[str, Any],
    payload: dict[str, Any],
    hostname: str | None,
    user_id: str | None = None,
    principal: dict[str, Any] | None = None,
    labels: dict[str, str] | None = None,
    ts: Any = None,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``principal`` wins over ``user_id`` (attributed people carry more than an id); ``source``
    adds to ``{"sensor": sensor}`` (e.g. a sequence number); ``ts`` defaults to now."""
    doc: dict[str, Any] = {
        "ts": datetime.now(UTC) if ts is None else ts,
        "endpoint": {"device_id": "pending", "hostname": hostname},
        "principal": principal if principal is not None else {"user_id": user_id},
        "agent": agent,
        "source": {"sensor": sensor, **(source or {})},
        "payload": payload,
    }
    if labels is not None:
        doc["labels"] = labels
    return doc

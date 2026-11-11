"""How much each queued item matters when the spool must choose.

Priority decides two things while the control plane is unreachable:

- **eviction**: when the spool is full, the lowest priority goes first (oldest first within a level);
- **send order**: after reconnecting, the highest priority is shipped first.

Findings are always CRITICAL and are never evicted. An event becomes CRITICAL when any rule hit
it, or later when a finding cites it as evidence or it came shortly before a finding in the same
session
(spool.py, ``context_seconds``). Otherwise its kind decides. M9 can move this table into the
central policy. Rationale per level, with real incidents: docs/incidents.md.
"""

from __future__ import annotations

from enum import IntEnum

from ..detect import Verdict
from ..schema import AgentEvent, EventKind


class Priority(IntEnum):
    LOW = 0  # chatter: useful for context, cheap to lose
    NORMAL = 1  # content the agent saw or was given
    HIGH = 2  # actions, inventory, and what the human asked for
    CRITICAL = 3  # rule hits, finding evidence, findings


KIND_PRIORITY: dict[EventKind, Priority] = {
    EventKind.TOOL_CALL: Priority.HIGH,
    EventKind.NET_EGRESS: Priority.HIGH,
    EventKind.INVENTORY_SNAPSHOT: Priority.HIGH,
    EventKind.SENSOR_HEALTH: Priority.HIGH,  # a silent enforcement point is a control gap
    EventKind.CONFIG_SNAPSHOT: Priority.HIGH,  # a weakened baseline is a control gap too
    EventKind.SESSION_START: Priority.HIGH,
    EventKind.SESSION_END: Priority.HIGH,
    # The user's own words show intent (an insider driving the agent) and the instructions the
    # agent was bound by (an ignored "code freeze"), so they rank with actions.
    EventKind.PROMPT_USER: Priority.HIGH,
    EventKind.TOOL_RESULT: Priority.NORMAL,
    EventKind.MESSAGE_ASSISTANT: Priority.LOW,
    EventKind.LLM_CALL: Priority.LOW,
}


def event_priority(event: AgentEvent, verdict: Verdict | None = None) -> Priority:
    if verdict is not None and verdict.hits:
        return Priority.CRITICAL
    return KIND_PRIORITY.get(event.kind, Priority.NORMAL)

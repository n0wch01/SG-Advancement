"""How much each queued item matters when the spool must choose.

Priority decides two things while the control plane is unreachable:

- **eviction**: when the spool is full, the lowest priority goes first (oldest first within a level);
- **send order**: after reconnecting, the highest priority is shipped first.

Findings are always CRITICAL and are never evicted. An event becomes CRITICAL when any rule hit
it, or later when a finding cites it as evidence (e.g. the earlier steps of a sequence rule).
Otherwise its kind decides. M9 can move this table into the central policy.
"""

from __future__ import annotations

from enum import IntEnum

from ..detect import Verdict
from ..schema import AgentEvent, EventKind


class Priority(IntEnum):
    LOW = 0  # chatter: useful for context, cheap to lose
    NORMAL = 1  # content the agent saw or was given
    HIGH = 2  # actions and inventory: what the agent did or could do
    CRITICAL = 3  # rule hits, finding evidence, findings


KIND_PRIORITY: dict[EventKind, Priority] = {
    EventKind.TOOL_CALL: Priority.HIGH,
    EventKind.NET_EGRESS: Priority.HIGH,
    EventKind.INVENTORY_SNAPSHOT: Priority.HIGH,
    EventKind.SESSION_START: Priority.HIGH,
    EventKind.SESSION_END: Priority.HIGH,
    EventKind.TOOL_RESULT: Priority.NORMAL,
    EventKind.PROMPT_USER: Priority.NORMAL,
    EventKind.MESSAGE_ASSISTANT: Priority.LOW,
    EventKind.LLM_CALL: Priority.LOW,
}


def event_priority(event: AgentEvent, verdict: Verdict | None = None) -> Priority:
    if verdict is not None and verdict.hits:
        return Priority.CRITICAL
    return KIND_PRIORITY.get(event.kind, Priority.NORMAL)

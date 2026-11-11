"""AgentEvent: the single normalized envelope every sensor emits.

Each sensor adapter translates its native telemetry (OpenClaw gateway frames, Claude Code hook
JSON, MCP JSON-RPC, LangGraph callbacks, ...) into one of the payload kinds below. Detection,
storage and the console only ever deal with this shape.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import AwareDatetime, Field

from .common import SCHEMA_VERSION, AgentRef, Endpoint, Principal, Source, StrictModel


class EventKind(StrEnum):
    SESSION_START = "session.start"
    SESSION_END = "session.end"
    PROMPT_USER = "prompt.user"
    MESSAGE_ASSISTANT = "message.assistant"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    LLM_CALL = "llm.call"
    NET_EGRESS = "net.egress"
    INVENTORY_SNAPSHOT = "inventory.snapshot"
    SENSOR_HEALTH = "sensor.health"


class ToolProviderKind(StrEnum):
    BUILTIN = "builtin"  # shipped with the agent (Bash, Read, exec, ...)
    PLUGIN = "plugin"  # agent-specific plugin/extension (OpenClaw plugin, Gemini extension)
    MCP = "mcp"  # tool served by an MCP server
    FUNCTION = "function"  # app-defined function tool (LangGraph @tool)
    UNKNOWN = "unknown"


class ToolProvider(StrictModel):
    kind: ToolProviderKind = ToolProviderKind.UNKNOWN
    plugin_id: str | None = None
    mcp_server: str | None = Field(default=None, description="MCP server name as configured by the client")
    mcp_server_url: str | None = None


class ToolDescriptor(StrictModel):
    """A tool as advertised to the model (used for inventory / tool-poisoning checks)."""

    name: str
    provider: ToolProvider = ToolProvider()
    description: str | None = None
    description_sha256: str | None = None


class PluginDescriptor(StrictModel):
    plugin_id: str
    version: str | None = None
    source: str | None = Field(default=None, description="Install source: registry, path, git url ...")
    enabled: bool = True


# ── payloads ────────────────────────────────────────────────────────────────


class SessionStart(StrictModel):
    kind: Literal[EventKind.SESSION_START] = EventKind.SESSION_START
    reason: str | None = None
    # How the agent was launched. Malware has driven installed agent CLIs with their safety
    # checks switched off (Nx "s1ngularity", 2025); these let rules see that. All optional:
    # sensors fill what their agent exposes.
    permission_mode: str | None = Field(
        default=None,
        description="Agent-native approval mode, e.g. default | plan | acceptEdits | bypassPermissions "
        "(Claude Code), yolo (Gemini CLI), full-auto (Codex CLI)",
    )
    interactive: bool | None = Field(
        default=None, description="False when started without a human at a terminal (-p, no TTY, CI)"
    )
    parent_process: str | None = Field(
        default=None, description="Executable that launched the agent, e.g. zsh, node, python"
    )


class SessionEnd(StrictModel):
    kind: Literal[EventKind.SESSION_END] = EventKind.SESSION_END
    reason: str | None = Field(default=None, description="completed | aborted | error | ...")


class UserPrompt(StrictModel):
    kind: Literal[EventKind.PROMPT_USER] = EventKind.PROMPT_USER
    text: str
    truncated: bool = False


class AssistantMessage(StrictModel):
    kind: Literal[EventKind.MESSAGE_ASSISTANT] = EventKind.MESSAGE_ASSISTANT
    text: str
    truncated: bool = False


class ToolCall(StrictModel):
    """Emitted *before* a tool executes. Sensors that can block (hooks, proxies) wait for the
    local policy verdict on this event."""

    kind: Literal[EventKind.TOOL_CALL] = EventKind.TOOL_CALL
    call_id: str
    tool: str
    provider: ToolProvider = ToolProvider()
    arguments: dict[str, Any] = Field(default_factory=dict, description="Redacted by the sensor")


class ToolResult(StrictModel):
    kind: Literal[EventKind.TOOL_RESULT] = EventKind.TOOL_RESULT
    call_id: str
    tool: str
    provider: ToolProvider = ToolProvider()
    ok: bool = True
    output_preview: str | None = Field(default=None, description="Head of the output, redacted")
    output_bytes: int | None = Field(default=None, ge=0)
    error: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)


class LlmCall(StrictModel):
    kind: Literal[EventKind.LLM_CALL] = EventKind.LLM_CALL
    provider: str = Field(description="anthropic | openai | google | ollama | ...")
    model: str
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)


class NetEgress(StrictModel):
    kind: Literal[EventKind.NET_EGRESS] = EventKind.NET_EGRESS
    method: str = "GET"
    url: str
    host: str
    bytes_out: int | None = Field(default=None, ge=0)
    destination: Literal["internal", "external", "unknown"] = "unknown"


class InventorySnapshot(StrictModel):
    kind: Literal[EventKind.INVENTORY_SNAPSHOT] = EventKind.INVENTORY_SNAPSHOT
    tools: tuple[ToolDescriptor, ...] = ()
    plugins: tuple[PluginDescriptor, ...] = ()
    mcp_servers: tuple[str, ...] = ()


class SensorHealth(StrictModel):
    """State of an enforcement or observation component, reported by the sensor itself.
    A component that goes quiet (e.g. a gateway plugin that stopped sending heartbeats) is a
    control gap: tool calls may now run without a pre-execution check."""

    kind: Literal[EventKind.SENSOR_HEALTH] = EventKind.SENSOR_HEALTH
    component: str = Field(description="e.g. openclaw_plugin")
    status: Literal["up", "lost", "recovered"]
    detail: str | None = None
    last_seen: AwareDatetime | None = Field(default=None, description="Last sign of life before this report")


Payload = Annotated[
    SessionStart
    | SessionEnd
    | UserPrompt
    | AssistantMessage
    | ToolCall
    | ToolResult
    | LlmCall
    | NetEgress
    | InventorySnapshot
    | SensorHealth,
    Field(discriminator="kind"),
]


def new_id() -> str:
    return uuid4().hex


class AgentEvent(StrictModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    event_id: str = Field(default_factory=new_id)
    ts: AwareDatetime = Field(description="When it happened on the endpoint (UTC recommended)")
    received_ts: AwareDatetime | None = Field(default=None, description="Set by the control plane")
    endpoint: Endpoint
    principal: Principal
    agent: AgentRef
    source: Source
    payload: Payload
    labels: dict[str, str] = Field(default_factory=dict, description="Free-form, e.g. scenario=S1")
    raw: dict[str, Any] | None = Field(default=None, description="Optional redacted native frame")

    @property
    def kind(self) -> EventKind:
        return self.payload.kind

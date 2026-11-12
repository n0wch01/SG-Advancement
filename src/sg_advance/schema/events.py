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
    CONFIG_SNAPSHOT = "config.snapshot"
    INTEGRITY_REPORT = "integrity.report"
    APPROVAL_RESOLVED = "approval.resolved"


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
    withheld: bool = Field(
        default=False,
        description="Text left on the endpoint: no rule hit, so only its length is sent (data minimization)",
    )
    text_chars: int | None = Field(default=None, ge=0, description="Length of the original text")


class AssistantMessage(StrictModel):
    kind: Literal[EventKind.MESSAGE_ASSISTANT] = EventKind.MESSAGE_ASSISTANT
    text: str
    truncated: bool = False
    withheld: bool = Field(
        default=False,
        description="Text left on the endpoint: no rule hit, so only its length is sent (data minimization)",
    )
    text_chars: int | None = Field(default=None, ge=0, description="Length of the original text")


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


class ExecPolicy(StrictModel):
    """Shell-execution policy at one scope. ``None`` means "not set here" (the agent's default)."""

    scope: str = Field(description='"global" or "agent:<id>"')
    security: str | None = Field(default=None, description="openclaw: deny | allowlist | full")
    ask: str | None = Field(default=None, description="openclaw: off | on-miss | always")
    mode: str | None = Field(default=None, description="openclaw: deny | allowlist | ask | auto | full")
    host: str | None = None
    elevated: bool | None = Field(default=None, description="Privileged command path enabled")


class RuntimePin(StrictModel):
    """Which runtime executes a model's turns. Tools that run inside a foreign runtime (e.g. a CLI
    backend) may never pass the gateway's pre-execution hooks."""

    scope: str = Field(description='"defaults" or "agent:<id>"')
    model: str
    runtime: str = Field(description='Pinned runtime id, or "default" when nothing pins it')


class ConfigSnapshot(StrictModel):
    """Security-relevant settings of an agent installation, read from its own config.

    Only allowlisted fields are copied: the config file also holds tokens and account details,
    which never leave the endpoint. Emitted at sensor start and whenever these fields change."""

    kind: Literal[EventKind.CONFIG_SNAPSHOT] = EventKind.CONFIG_SNAPSHOT
    product: str = Field(description="e.g. openclaw")
    path: str | None = Field(default=None, description="Config file the values came from")
    changed: tuple[str, ...] = Field(default=(), description="Fields that differ from the previous snapshot")
    guard_plugin: Literal["enabled", "disabled", "missing"] | None = Field(
        default=None, description="The SG-Advance enforcement plugin as the config leaves it"
    )
    guard_detail: str | None = None
    plugins: tuple[PluginDescriptor, ...] = ()
    exec_policies: tuple[ExecPolicy, ...] = ()
    runtimes: tuple[RuntimePin, ...] = ()


class ComponentIntegrity(StrictModel):
    """One installed unit of agent code compared with what its publisher signed."""

    component: str = Field(description='"core" or "plugin:<id>"')
    package: str | None = Field(
        default=None, description='npm package expected to contain it, e.g. "openclaw"'
    )
    version: str | None = None
    origin: str | None = Field(
        default=None, description="openclaw: core | bundled | global | config | workspace"
    )
    path: str | None = Field(default=None, description="Installed directory that was hashed")
    digest: str = Field(description="integrity.tree_digest of the installed files")
    integrity: Literal["verified", "mismatch", "pending", "unknown"] = Field(
        description="verified: matches a signed package; mismatch: differs from it (tampered); "
        "pending: no verified digests for this version yet; unknown: no package or pin vouches for it"
    )
    trust: Literal["approved", "trusted", "cooling", "revoked", "rejected", "unverified"] = Field(
        default="unverified", description="Status of the package version it belongs to (policy manifests)"
    )
    enabled: bool = True


class IntegrityReport(StrictModel):
    """Installed agent code vs. known-good digests from the policy. Sent when anything changes."""

    kind: Literal[EventKind.INTEGRITY_REPORT] = EventKind.INTEGRITY_REPORT
    product: str = Field(description="e.g. openclaw")
    version: str | None = None
    core: ComponentIntegrity | None = None
    plugins: tuple[ComponentIntegrity, ...] = ()


class ApprovalResolution(StrictModel):
    """A person's answer to a pre-execution approval prompt (``require_approval``).

    Links back to the ``tool.call`` event and findings that asked for it, so security can audit
    what users approved after the fact. ``approver`` is who pressed the button when the agent
    reports it; OpenClaw plugin approvals do not, so it is usually ``None`` (see the requester labels).
    """

    kind: Literal[EventKind.APPROVAL_RESOLVED] = EventKind.APPROVAL_RESOLVED
    call_id: str
    tool: str
    decision: Literal["allow-once", "allow-always", "deny", "timeout", "cancelled"]
    approved: bool = Field(description="decision is allow-once or allow-always")
    rule_ids: tuple[str, ...] = Field(default=(), description="Rules that asked for approval")
    max_severity: str | None = Field(default=None, description="Highest severity among those rules")
    request_event_id: str | None = Field(default=None, description="The tool.call event that was held")
    finding_ids: tuple[str, ...] = ()
    requested_at: AwareDatetime | None = None
    wait_ms: int | None = Field(default=None, ge=0, description="Time the prompt was open")
    judged_by: Literal["daemon", "degraded", "fallback"] = Field(
        default="daemon", description="Which path asked: daemon, cached-policy CLI, or risk-tier fallback"
    )
    approver: str | None = None


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
    | SensorHealth
    | ConfigSnapshot
    | IntegrityReport
    | ApprovalResolution,
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

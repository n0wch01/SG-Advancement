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
    OPERATOR_ACTION = "operator.action"
    INSTALL_SNAPSHOT = "install.snapshot"


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


class SkillDescriptor(StrictModel):
    """An agent skill (instructions + scripts the model can load), e.g. OpenClaw ``SKILL.md``."""

    name: str
    source: str | None = Field(
        default=None, description="Where it came from, e.g. openclaw-bundled / -extra / -managed / -workspace"
    )
    ref: str | None = Field(default=None, description="source:name, what allowlists match on")
    enabled: bool = True
    eligible: bool | None = Field(default=None, description="Requirements met, so the agent can use it")
    model_visible: bool | None = None
    description: str | None = None
    description_sha256: str | None = None
    path: str | None = Field(default=None, description="Installed skill directory")
    digest: str | None = Field(default=None, description="integrity.tree_digest of the skill directory")
    integrity: Literal["verified", "mismatch", "unknown"] | None = Field(
        default=None,
        description="verified: matches a digest security approved; mismatch: an approved skill changed; "
        "unknown: nobody approved it. None: not checked (bundled with the agent, or files not readable)",
    )
    trust: str | None = Field(
        default=None, description="Status of the approval it matched (approved / revoked)"
    )


class ModelRuntime(StrictModel):
    """The runtime a selectable model would run with on the gateway right now (``models.list``)."""

    model: str = Field(description="provider/id")
    runtime: str | None = Field(default=None, description="openclaw agentRuntime.id, e.g. openclaw / codex")
    source: str | None = Field(
        default=None,
        description="Where the runtime came from: model (pinned) / implicit (OpenClaw chose) / ...",
    )


class SessionBinding(StrictModel):
    """The runtime one live conversation is bound to, compared with what its model would get now (T19)."""

    session_key: str
    model: str | None = Field(default=None, description="provider/id the conversation uses")
    runtime: str | None = Field(
        default=None, description="Runtime the conversation reports (agentRuntime.id)"
    )
    runtime_source: str | None = None
    locked: bool | None = Field(default=None, description="openclaw runtimeSelectionLocked")
    expected_runtime: str | None = Field(
        default=None, description="Runtime its model resolves to now (models.list); None if not listed"
    )
    binding: Literal["current", "stale", "unpinned", "unknown"] = Field(
        default="unknown",
        description="current: same as its model's pinned runtime; stale: bound to another runtime than the "
        "pin (config changed after it started); unpinned: its model has no pin; unknown: model not listed",
    )
    active: bool | None = Field(default=None, description="A run is in progress")


class InventorySnapshot(StrictModel):
    """What one agent can use. Multi-agent gateways send one snapshot per agent (``agent_id``)."""

    kind: Literal[EventKind.INVENTORY_SNAPSHOT] = EventKind.INVENTORY_SNAPSHOT
    agent_id: str | None = Field(default=None, description="Agent on a multi-agent gateway")
    model: str | None = None
    runtime: str | None = None
    permission_mode: str | None = Field(default=None, description="The agent's default permission mode")
    tools: tuple[ToolDescriptor, ...] = ()
    plugins: tuple[PluginDescriptor, ...] = ()
    skills: tuple[SkillDescriptor, ...] = ()
    mcp_servers: tuple[str, ...] = ()
    model_runtimes: tuple[ModelRuntime, ...] = Field(
        default=(), description="Selectable models and the runtime each runs with (gateway view)"
    )
    sessions: tuple[SessionBinding, ...] = Field(
        default=(), description="Live (unarchived) conversations of this agent and their runtime binding"
    )


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


class DelegationGrant(StrictModel):
    """openclaw ``agents.entries.<id>.subagents.delegateToolsTo``: the agent's own ``tools.deny`` is
    lifted for these target agents when it hands work to them (follow-up scenario 3, 2026-11-14)."""

    agent_id: str
    to: tuple[str, ...] = ()


class SandboxPolicy(StrictModel):
    """Where an agent's tools run. ``mode_source: default`` means not configured: the agent's
    built-in default applies (OpenClaw: ``off``, i.e. directly on the host)."""

    scope: str = Field(description='"defaults" or "agent:<id>"')
    mode: str | None = Field(default=None, description="openclaw: off | non-main | all (effective value)")
    mode_source: Literal["set", "default"] | None = None
    workspace_access: str | None = Field(default=None, description="openclaw: none | ro | rw")
    scope_kind: str | None = Field(default=None, description="openclaw: session | agent | shared")
    elevated_default: str | None = Field(
        default=None,
        description="openclaw agents.defaults.elevatedDefault: off | on | ask | full (effective)",
    )


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
    guard_scope: Literal["managed", "user"] | None = Field(
        default=None,
        description="Claude Code (M6): the guard hook is in managed settings (users cannot remove it) "
        "or only in the user's own settings (they can)",
    )
    default_mode: str | None = Field(
        default=None, description="Agent-native default permission mode, e.g. bypassPermissions (Claude Code)"
    )
    bypass_disabled: bool | None = Field(
        default=None, description="Policy forbids the bypass-permissions mode (Claude Code managed settings)"
    )
    plugins: tuple[PluginDescriptor, ...] = ()
    exec_policies: tuple[ExecPolicy, ...] = ()
    runtimes: tuple[RuntimePin, ...] = ()
    sandboxes: tuple[SandboxPolicy, ...] = ()
    delegation_grants: tuple[DelegationGrant, ...] = Field(
        default=(), description="openclaw: agents whose tool denials are lifted for named delegation targets"
    )


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
    """An answer to a pre-execution approval prompt (``require_approval`` or ``security_approval``).

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
    via: Literal["user", "security"] = Field(
        default="user",
        description="Who was asked: the person in the agent UI (require_approval), or security in the "
        "console (security_approval, M11; approver = who decided there)",
    )


class OperatorAction(StrictModel):
    """A person acting on the gateway's control surface: answering an approval prompt, stopping a
    run, archiving or deleting a conversation. Recorded by the audit proxy between the identity
    proxy and the gateway, so ``principal`` is the person who acted (from SSO), not the one whose
    agent ran. OpenClaw itself only stores the client app as the resolver.

    Only control messages are read; conversations pass through untouched.
    """

    kind: Literal[EventKind.OPERATOR_ACTION] = EventKind.OPERATOR_ACTION
    action: Literal[
        "approval.resolve",
        "run.abort",
        "session.delete",
        "session.archive",
        "session.unarchive",
        "session.privilege",
    ]
    method: str = Field(description="Gateway RPC the person's client sent, e.g. plugin.approval.resolve")
    ok: bool | None = Field(default=None, description="Gateway accepted it; None if no answer was seen")
    error: str | None = Field(default=None, description="Gateway error code when refused")
    decision: str | None = Field(default=None, description="approval.resolve: allow-once, deny, ...")
    approval_id: str | None = None
    call_id: str | None = Field(
        default=None, description="Tool call the approval was for, when the gateway said"
    )
    tool: str | None = None
    target_session_id: str | None = Field(
        default=None, description="Session of the approval or the stopped run"
    )
    target_run_id: str | None = None
    archived_only: bool | None = Field(
        default=None, description="session.delete: only if already archived (what members may do)"
    )
    delete_transcript: bool | None = Field(default=None, description="session.delete: transcript removed too")
    changes: tuple[str, ...] = Field(
        default=(),
        description='session.privilege: "field=value" per permission field set (e.g. permissionMode=full)',
    )


class McpServerRef(StrictModel):
    """An MCP server an agent is configured to use (shadow AI discovery). Only what identifies it
    leaves the endpoint: no arguments, no environment, no query string (they can hold tokens)."""

    name: str
    transport: Literal["http", "sse", "stdio", "unknown"] = "unknown"
    url: str | None = Field(default=None, description="Remote servers: scheme://host/path, query removed")
    command: str | None = Field(default=None, description="Local (stdio) servers: the executable's name only")
    route: Literal["gateway", "direct", "local", "unknown"] = Field(
        default="unknown",
        description="gateway: through the company MCP gateway; direct: a remote server reached around it; "
        "local: a stdio process on the endpoint; unknown: no gateway configured on this sensor",
    )
    scope: str | None = Field(default=None, description="user | project (where the agent's config lists it)")


class InstallSnapshot(StrictModel):
    """One agent installation found on the endpoint, managed or not (shadow AI discovery).

    Sent per install when it is first seen, when its state changes, and once more with
    ``present=false`` when it disappears. Only the product's own traces are read (its binary,
    state directory, service file, its gateway port on 127.0.0.1); nothing else on the machine."""

    kind: Literal[EventKind.INSTALL_SNAPSHOT] = EventKind.INSTALL_SNAPSHOT
    product: str = Field(description="e.g. openclaw")
    instance: str = Field(
        description="What identifies this install: its state dir, or the code path if never set up"
    )
    present: bool = Field(default=True, description="false: the install was seen before and is gone now")
    changed: tuple[str, ...] = Field(default=(), description="Fields that differ from the previous snapshot")
    version: str | None = None
    install_path: str | None = Field(default=None, description="Package directory of the code that runs it")
    install_source: str | None = Field(
        default=None, description="npm-global | nvm | pnpm | volta | app | other (from the path)"
    )
    config_path: str | None = None
    configured: bool = Field(default=False, description="A config file exists (the install was set up)")
    services: tuple[str, ...] = Field(default=(), description="launchd / systemd units that start it")
    running: bool | None = Field(default=None, description="Its gateway port answers on 127.0.0.1")
    bind: str | None = Field(default=None, description="openclaw gateway.bind (default loopback)")
    bind_scope: Literal["loopback", "network"] | None = None
    guard_plugin: Literal["enabled", "disabled", "missing"] | None = Field(
        default=None, description="The SG-Advance plugin as the install's config leaves it"
    )
    watched: bool = Field(default=False, description="This sensor watches the install's config and gateway")
    managed: bool = Field(default=False, description="configured, guard plugin enabled and watched")
    unmanaged_reasons: tuple[str, ...] = ()
    mcp_servers: tuple[McpServerRef, ...] = Field(
        default=(), description="MCP servers this agent is configured with (M8 shadow AI discovery)"
    )


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
    | ApprovalResolution
    | OperatorAction
    | InstallSnapshot,
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

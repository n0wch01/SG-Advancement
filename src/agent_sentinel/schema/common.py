"""Shared building blocks: identity context of *who / where / which agent / which sensor*."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"


class StrictModel(BaseModel):
    """Base for all wire models: unknown fields are rejected, instances are immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AgentType(StrEnum):
    """The AI agent product that produced the activity."""

    OPENCLAW = "openclaw"
    CLAUDE_CODE = "claude_code"
    LANGGRAPH = "langgraph"
    GEMINI_CLI = "gemini_cli"
    CODEX_CLI = "codex_cli"
    UNKNOWN = "unknown"


class SensorType(StrEnum):
    """How the activity was observed. One agent can be seen by several sensors
    (e.g. Claude Code via its hooks *and* via the MCP proxy)."""

    OPENCLAW_GATEWAY = "openclaw_gateway"  # gateway WebSocket subscription
    CLAUDE_CODE_HOOK = "claude_code_hook"  # PreToolUse / PostToolUse ... hooks
    GEMINI_CLI_HOOK = "gemini_cli_hook"
    CODEX_CLI_HOOK = "codex_cli_hook"
    LANGGRAPH_CALLBACK = "langgraph_callback"  # in-process callback handler
    MCP_PROXY = "mcp_proxy"  # sits between any MCP client and server
    LLM_PROXY = "llm_proxy"  # sits between agent and LLM API
    EGRESS_PROXY = "egress_proxy"  # outbound HTTP interception


class Endpoint(StrictModel):
    """The machine (container / VM / PC) the agent runs on."""

    device_id: str = Field(min_length=1, description="Stable id issued at enrollment")
    hostname: str | None = None
    os: str | None = None
    ip: str | None = None


class Principal(StrictModel):
    """The human the agent acts on behalf of."""

    user_id: str = Field(min_length=1)
    display_name: str | None = None
    groups: tuple[str, ...] = ()


class AgentRef(StrictModel):
    """Which agent instance and conversation the event belongs to."""

    type: AgentType
    session_id: str = Field(min_length=1, description="Agent-native session/conversation id")
    version: str | None = None
    run_id: str | None = Field(default=None, description="One agent turn/run inside the session, if known")
    model: str | None = None
    cwd: str | None = None


class Source(StrictModel):
    """The sensor/adapter that emitted the event."""

    sensor: SensorType
    sensor_version: str = "0.1.0"
    seq: int | None = Field(default=None, ge=0, description="Per-sensor monotonic sequence number")

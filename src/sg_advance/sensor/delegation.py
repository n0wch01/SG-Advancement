"""Follow-up scenario 3 (CLAUDE.md): a child granted more permission than its parent
(docs/delegation-permissions.md). Delegation control, kept apart from data lineage (lineage.py).

Claude Code subagents are defined in ``.claude/agents/*.md`` (project, then user). Their frontmatter
can set ``permissionMode``, ``tools``, ``disallowedTools`` and ``mcpServers``. Two checks, both only
labels (``labels.sga_delegation_escalation``); the signed rules decide:

- **Before the child exists** (the parent's Task/Agent call): the definition is compared with the
  parent. The parent's mode is the calling hook's ``permission_mode``; its tools are all tools for the
  main conversation, or its own definition's when the parent is a subagent. ``mode:<parent>→<child>``,
  ``tools:+<more>``, ``mcp:+<servers the child starts itself>``.
- **While the child runs**: a subagent's call that reports a broader ``permission_mode`` than the main
  conversation last did gets ``runtime-mode:<parent>→<child>``.

Effective mode, following Claude Code's documented rules: a parent in bypassPermissions / acceptEdits
/ auto passes its own mode down; a plan parent keeps the child in plan; under default / dontAsk the
child's own mode applies. A child asking for bypassPermissions under a narrower parent counts as an
escalation even though Claude Code v2.1.267+ holds it at the parent's mode (older versions do not).

The definition files come from the working copy (a cloned repository can bring its own). They are
read, never trusted: only their permissions are compared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..schema import AgentEvent, EventKind
from .tools import CLAUDE_SUBAGENT_READ_ONLY

LABEL = "sga_delegation_escalation"
DEF_LABEL = "sga_delegation_def"
CHILD_LABEL = "sga_delegation_child"
LABELS = (LABEL, DEF_LABEL, CHILD_LABEL)

DELEGATION_TOOLS = {"Task", "Agent"}
MODE_RANK = {
    "plan": 0,
    "dontAsk": 1,
    "default": 2,
    "manual": 2,
    "acceptEdits": 3,
    "auto": 4,
    "bypassPermissions": 5,
}
_PASS_DOWN = {"bypassPermissions", "acceptEdits", "auto"}
READ_ONLY = CLAUDE_SUBAGENT_READ_ONLY
# Built-in subagent types (no file): read-only explorers, and the general one that inherits everything.
BUILTIN: dict[str, dict[str, Any]] = {
    "Explore": {"tools": sorted(READ_ONLY)},
    "Plan": {"tools": sorted(READ_ONLY)},
    "general-purpose": {},
}
_NAME = re.compile(r"^[\w.:-]{1,100}$")
_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.S)
MAX_FILES = 300


@dataclass(frozen=True)
class AgentDef:
    name: str
    path: str  # where it was read, or "builtin"
    tools: frozenset[str] | None = None  # None = every tool (inherited)
    disallowed: frozenset[str] = frozenset()
    mode: str | None = None
    mcp_inline: tuple[str, ...] = ()  # servers the definition starts itself (not just names)


@dataclass(frozen=True)
class ToolSet:
    """Tools an agent has: everything except ``minus``, or exactly ``only``."""

    only: frozenset[str] | None = None
    minus: frozenset[str] = field(default_factory=frozenset)

    def extra_over(self, parent: ToolSet) -> list[str]:
        """Tools this set has that ``parent`` does not ("*" = everything beyond the parent's list)."""
        if parent.only is None:  # parent: all but parent.minus
            if self.only is None:
                return sorted(parent.minus - self.minus)
            return sorted(self.only & parent.minus)
        if self.only is None:
            return ["*"]
        return sorted(self.only - parent.only)


def _tool_list(value: Any) -> frozenset[str] | None:
    if value is None:
        return None
    items = value.split(",") if isinstance(value, str) else value if isinstance(value, list) else []
    names = {re.sub(r"\(.*\)$", "", str(t)).strip() for t in items}  # "Agent(worker)" -> "Agent"
    return frozenset(n for n in names if n)


def _parse(path: Path) -> AgentDef | None:
    try:
        m = _FRONTMATTER.match(path.read_text(encoding="utf-8")[:20000])
        meta = yaml.safe_load(m.group(1)) if m else None
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None
    if not isinstance(meta, dict) or not isinstance(meta.get("name"), str):
        return None
    servers = meta.get("mcpServers")
    inline: list[str] = []
    if isinstance(servers, dict):
        inline = [str(k) for k, v in servers.items() if isinstance(v, dict)]
    elif isinstance(servers, list):
        for s in servers:
            if isinstance(s, dict):
                inline += [str(k) for k, v in s.items() if isinstance(v, dict)]
    mode = meta.get("permissionMode")
    return AgentDef(
        name=meta["name"],
        path=str(path),
        tools=_tool_list(meta.get("tools")),
        disallowed=_tool_list(meta.get("disallowedTools")) or frozenset(),
        mode=mode if isinstance(mode, str) else None,
        mcp_inline=tuple(sorted(inline)),
    )


def find_def(name: str, cwd: str | None, home: Path) -> AgentDef | None:
    """The definition Claude Code would use: project (.claude/agents under the working directory),
    then the user's (~/.claude/agents), then the built-in types."""
    if not _NAME.match(name):
        return None
    dirs = ([Path(cwd) / ".claude" / "agents"] if cwd else []) + [home / ".claude" / "agents"]
    for d in dirs:
        try:
            files = sorted(d.glob("*.md"))[:MAX_FILES] if d.is_dir() else []
        except OSError:
            files = []
        for f in files:
            parsed = _parse(f)
            if parsed is not None and parsed.name == name:
                return parsed
    if name in BUILTIN:
        b = BUILTIN[name]
        return AgentDef(name=name, path="builtin", tools=_tool_list(b.get("tools")))
    return None


def effective_mode(parent: str, child: str | None) -> str:
    if child is None or child not in MODE_RANK:
        return parent
    if parent in _PASS_DOWN:
        return parent
    if parent == "plan":
        return "plan"
    return child  # default / dontAsk: the child's own (bypassPermissions counted as asked: see module doc)


def _rank(mode: str | None) -> int | None:
    return MODE_RANK.get(mode) if mode else None


def toolset(d: AgentDef | None) -> ToolSet:
    if d is None:
        return ToolSet()
    if d.tools is None:
        return ToolSet(minus=d.disallowed)
    return ToolSet(only=d.tools - d.disallowed)


# OpenClaw (2026-11-14). Session permission modes, narrowest first (docs: gateway/permission-modes).
# A new session takes its agent's configured mode, so sessions_spawn with another ``agentId`` starts the
# child at that agent's default. Tools are not compared: OpenClaw already passes the caller's tool
# ceiling down (docs: tools/subagents/tool-policy), except ``delegateToolsTo`` grants (config rule).
OPENCLAW_RANK = {"read-only": 0, "guarded": 1, "workspace": 2, "full": 3}
_AGENT_KEY = re.compile(r"^agent:([^:]+):")


def openclaw_agent(session_key: str | None) -> str | None:
    m = _AGENT_KEY.match(session_key or "")
    return m.group(1) if m else None


def _sandboxed(mode: str | None, main: bool) -> bool:
    """OpenClaw sandbox modes: off | non-main (every session but the agent's main one) | all."""
    return mode == "all" or (mode == "non-main" and not main)


class DelegationChecker:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or Path.home()
        self.root_modes: dict[str, str] = {}  # main conversation -> its last reported permission mode
        self.openclaw_modes: dict[str, str] = {}  # agent id -> default permission mode (inventory)
        self.openclaw_sandbox: dict[str, str] = {}  # "defaults" | agent id -> sandbox mode (config)

    def observe(self, event: AgentEvent) -> None:
        """Learn OpenClaw agents' default permission modes and sandboxes from the snapshots."""
        p = event.payload
        if event.kind is EventKind.INVENTORY_SNAPSHOT:
            mode, aid = getattr(p, "permission_mode", None), getattr(p, "agent_id", None)
            if isinstance(mode, str) and isinstance(aid, str) and mode in OPENCLAW_RANK:
                self.openclaw_modes[aid] = mode
        elif event.kind is EventKind.CONFIG_SNAPSHOT and getattr(p, "product", None) == "openclaw":
            for sb in getattr(p, "sandboxes", ()) or ():
                key = "defaults" if sb.scope == "defaults" else sb.scope.removeprefix("agent:")
                if sb.mode:
                    self.openclaw_sandbox[key] = sb.mode

    def _sandbox_of(self, agent_id: str) -> str | None:
        return self.openclaw_sandbox.get(agent_id) or self.openclaw_sandbox.get("defaults")

    def labels_for(self, event: AgentEvent) -> dict[str, str]:
        if event.kind is not EventKind.TOOL_CALL:
            self.observe(event)
            return {}
        if event.agent.type == "openclaw":
            return self._openclaw(event)
        mode = event.labels.get("claude_code.permission_mode")
        child_id = event.labels.get("claude_code.agent_id")
        root = event.agent.root_session_id or event.agent.session_id
        if mode in MODE_RANK and not child_id:
            self.root_modes[event.agent.session_id] = mode
        labels: dict[str, str] = {}
        parent = self.root_modes.get(root) if child_id and mode in MODE_RANK else None
        if parent is not None and MODE_RANK[mode] > MODE_RANK[parent]:  # type: ignore[index]
            labels[LABEL] = f"runtime-mode:{parent}→{mode}"
        if getattr(event.payload, "tool", "") in DELEGATION_TOOLS:
            labels |= self._at_delegation(event, mode)
        return labels

    def _at_delegation(self, event: AgentEvent, mode: str | None) -> dict[str, str]:
        args = getattr(event.payload, "arguments", {}) or {}
        name = args.get("subagent_type") or "general-purpose"
        if not isinstance(name, str):
            return {}
        cwd = event.agent.cwd
        child = find_def(name, cwd, self.home)
        if child is None:
            return {CHILD_LABEL: name[:100], DEF_LABEL: "unknown"}
        parent_type = (
            event.labels.get("claude_code.agent_type") if event.labels.get("claude_code.agent_id") else None
        )
        parent_def = find_def(parent_type, cwd, self.home) if parent_type else None
        parts: list[str] = []
        if mode in MODE_RANK:
            child_mode = effective_mode(mode, child.mode)
            if MODE_RANK[child_mode] > MODE_RANK[mode]:
                parts.append(f"mode:{mode}→{child_mode}")
        if parent_def is not None and (extra := toolset(child).extra_over(toolset(parent_def))):
            parts.append("tools:+" + ",".join(extra))
        if child.mcp_inline:
            parts.append("mcp:+" + ",".join(child.mcp_inline))
        out = {CHILD_LABEL: name[:100], DEF_LABEL: child.path[:300]}
        if parts:
            out[LABEL] = ";".join(parts)[:500]
        return out

    def _openclaw(self, event: AgentEvent) -> dict[str, str]:
        labels: dict[str, str] = {}
        me = openclaw_agent(event.agent.session_id)
        root = openclaw_agent(event.agent.root_session_id)
        mine, roots = self.openclaw_modes.get(me or ""), self.openclaw_modes.get(root or "")
        cross = bool(event.agent.parent_session_id and me and root and me != root and mine and roots)
        if cross and OPENCLAW_RANK[mine] > OPENCLAW_RANK[roots]:  # type: ignore[index]  # child above the top
            labels[LABEL] = f"runtime-mode:{roots}→{mine}"
        if getattr(event.payload, "tool", "") != "sessions_spawn" or not me:
            return labels
        args = getattr(event.payload, "arguments", {}) or {}
        target = args.get("agentId") if isinstance(args.get("agentId"), str) else me
        out: dict[str, str] = {
            CHILD_LABEL: target[:100],
            DEF_LABEL: f"openclaw:agents.entries.{target}"[:300],
        }
        parts: list[str] = []
        parent_mode, child_mode = self.openclaw_modes.get(me), self.openclaw_modes.get(target)
        if (
            target != me
            and parent_mode
            and child_mode
            and OPENCLAW_RANK[child_mode] > OPENCLAW_RANK[parent_mode]
        ):
            parts.append(f"mode:{parent_mode}→{child_mode}")
        parent_main = event.agent.parent_session_id is None and (event.agent.session_id or "").endswith(
            ":main"
        )
        parent_boxed = _sandboxed(self._sandbox_of(me), main=parent_main)
        child_boxed = args.get("sandbox") == "require" or _sandboxed(self._sandbox_of(target), main=False)
        if parent_boxed and not child_boxed:
            parts.append("sandbox:on→off")
        if parts:
            out[LABEL] = ";".join(parts)
        return labels | out

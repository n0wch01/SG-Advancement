"""Tool names by what the tool does, in one place (refactor 2026-11-15).

Every judgement that depends on a tool's *kind* reads these sets: the hook's no-policy fallback, the
lineage destinations (docs/lineage.md), downloaded-file tracking and the delegation checks. Before,
each module kept its own copy and they drifted. The rule files and the OpenClaw plugin cannot import
this module; ``tests/test_tools.py`` holds their lists to these sets.

Claude Code and OpenClaw name their tools differently; both are listed. Read-only tools are kept per
agent because "read-only" is used for different decisions (what passes with no policy, and where data
can go): merging them would change those decisions.
"""

from __future__ import annotations

CLAUDE_READ_ONLY = frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoRead", "TodoWrite"})
# The OpenClaw plugin's own no-policy list (integrations/openclaw-plugin/policy.ts DEFAULT_READ_ONLY).
OPENCLAW_READ_ONLY = frozenset({"read", "memory_search", "memory_get", "session_status"})

FILE_WRITE = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "write", "edit", "apply_patch"})
WEB = frozenset({"WebFetch", "web_fetch", "fetch", "browser"})
SEARCH = frozenset({"WebSearch", "web_search"})
# PowerShell: Windows Claude Code's shell tool (laptop, 2026-11-15). Without it a local PowerShell read
# counted as input of unknown origin, and a following delete as "after external input" (critical).
SHELL = frozenset({"Bash", "PowerShell", "exec", "shell", "bash", "run_command", "process"})

# Claude Code's own tools that touch neither files nor the network: loading tool schemas (ToolSearch,
# before MCP calls), asking the person, plan mode, loading a local skill. Not read-only for the hook's
# no-policy fallback (that list stays as it is); only "where did this input come from" (laptop, 2026-11-15:
# ToolSearch's result counted as unknown input, so a following delete looked like "after external input").
CLAUDE_INTERNAL = frozenset({"ToolSearch", "AskUserQuestion", "ExitPlanMode", "Skill"})

# Where data stays on the PC (lineage destination "local"): Claude Code's read-only and internal tools,
# and OpenClaw's read.
LOCAL = CLAUDE_READ_ONLY | CLAUDE_INTERNAL | {"read"}
# What a Claude Code subagent may hold and still count as read-only (delegation checks): it reads the
# workspace and the web but changes nothing.
CLAUDE_SUBAGENT_READ_ONLY = CLAUDE_READ_ONLY | {"WebFetch", "WebSearch"}

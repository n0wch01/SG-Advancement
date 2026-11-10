# CLAUDE.md

Solo portfolio project: a central policy and threat control plane for heterogeneous AI agents.
It was rebuilt from the team project `~/Desktop/SG/ajou-samsung-giants`, an OpenClaw-only MVP. Reuse code from it where useful.

- Target agents: OpenClaw, Claude Code, MCP proxy, LangGraph + Ollama, Gemini CLI, Codex CLI.
- Demo: Docker Compose locally (simulated employees + `internet-sim` attacker net), later other PCs/VMs.
- Progress and next milestone: `docs/roadmap.md` (update its status column when a milestone completes).
- Docs are written in Korean; code, identifiers and comments in English.

## Commands

```bash
uv sync
uv run pytest
uvx ruff check src tests scripts
uv run python scripts/export_schema.py   # after any change in src/agent_sentinel/schema/
```

## Conventions

- Every sensor adapter emits only `agent_sentinel.schema.AgentEvent` v1. Detection rules never see agent-native formats.
- Schema changes: add fields with defaults; regenerate `schemas/`; add or adjust `examples/events/*.jsonl`.
- Sensors redact secrets before events leave the endpoint.
- New behaviour needs tests. Each milestone should end in a demoable state.

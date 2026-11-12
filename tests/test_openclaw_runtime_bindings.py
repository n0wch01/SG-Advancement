"""T19 (M5d): the runtime each selectable model gets, and the one each live conversation is bound to.

Payload shapes are trimmed from OpenClaw 2026.11.3 ``models.list`` / ``sessions.list`` (team gateway).
"""

from __future__ import annotations

from typing import Any

from conftest import ROOT
from sg_advance.detect import Engine, RuleSet
from sg_advance.sensor.adapters.openclaw import OpenClawMapper


def rt(rid: str, source: str) -> dict[str, Any]:
    return {"id": rid, "cloudPlacementSupported": rid == "openclaw", "source": source}


MODELS = {
    "models": [
        {
            "id": "gpt-6-luna",
            "provider": "openai",
            "agentRuntime": rt("openclaw", "model"),
            "available": True,
        },
        {
            "id": "gpt-6.1-sol",
            "provider": "openai",
            "agentRuntime": rt("codex", "implicit"),
            "available": True,
        },
        {
            "id": "gpt-5.5-pro",
            "provider": "openai",
            "agentRuntime": rt("codex", "implicit"),
            "available": False,
        },
    ],
    "providerOutcomes": [{"provider": "openai", "profileId": "openai:someone@example.test"}],
}


def session(key: str, model: str, runtime: str, **extra: Any) -> dict[str, Any]:
    return {
        "key": key,
        "agentId": "main",
        "modelProvider": "openai",
        "model": model,
        "agentRuntime": rt(runtime, "model"),
        "runtimeSelectionLocked": True,
        "hasActiveRun": False,
        "updatedAt": 1,
        **extra,
    }


SESSIONS = [
    session("agent:main:dashboard:luna", "gpt-6-luna", "openclaw"),
    # Started while Luna ran on Codex; Luna is pinned to openclaw now, the conversation keeps Codex.
    session("agent:main:dashboard:sol", "gpt-6-luna", "codex", updatedAt=5),
    # Live 2026-11-12: a new chat switched to unpinned Sol kept the openclaw runtime it was created with.
    session("agent:main:dashboard:switched", "gpt-6.1-sol", "openclaw"),
    session("agent:main:dashboard:old", "gpt-4-legacy", "codex"),
    session("agent:main:dashboard:gone", "gpt-6-luna", "codex", archived=True),
    session("agent:research:main", "gpt-6-luna", "claude-cli", agentId="research"),
]


def inventory(agent_id: str = "main") -> dict[str, Any]:
    ev = OpenClawMapper("team-gateway").inventory(
        {"agentId": agent_id, "groups": []}, {"id": agent_id}, models=MODELS, sessions=SESSIONS
    )
    return ev.model_dump(mode="json")["payload"]


def test_model_runtimes_list_only_selectable_models_without_account_details() -> None:
    p = inventory()
    assert p["model_runtimes"] == [
        {"model": "openai/gpt-6-luna", "runtime": "openclaw", "source": "model"},
        {"model": "openai/gpt-6.1-sol", "runtime": "codex", "source": "implicit"},
    ]
    assert "someone@example.test" not in str(p)


def test_session_bindings_compare_with_the_models_runtime_now() -> None:
    p = inventory()
    got = {s["session_key"]: (s["runtime"], s["expected_runtime"], s["binding"]) for s in p["sessions"]}
    assert got == {
        "agent:main:dashboard:luna": ("openclaw", "openclaw", "current"),
        "agent:main:dashboard:sol": ("codex", "openclaw", "stale"),
        "agent:main:dashboard:switched": ("openclaw", "codex", "unpinned"),  # no company pin to follow
        "agent:main:dashboard:old": ("codex", None, "unknown"),  # model no longer listed
    }  # archived and other agents' conversations are left out
    assert p["sessions"][0]["session_key"] == "agent:main:dashboard:sol"  # most recently updated first
    assert p["sessions"][0]["locked"] is True and p["sessions"][0]["active"] is False
    research = inventory("research")["sessions"]
    assert [s["runtime"] for s in research] == ["claude-cli"]


def test_rules_on_the_live_runtime_view() -> None:
    engine = Engine(RuleSet.load(ROOT / "rules"))
    mapper = OpenClawMapper("team-gateway")
    main = mapper.inventory({"groups": []}, {"id": "main"}, models=MODELS, sessions=SESSIONS)
    research = mapper.inventory({"groups": []}, {"id": "research"}, models=MODELS, sessions=SESSIONS)
    hits = set(engine.process(main).rule_ids)
    assert {"openclaw-model-runtime-unpinned", "openclaw-session-runtime-stale"} <= hits
    assert "openclaw-session-runtime-unapproved" in engine.process(research).rule_ids


def test_gateways_without_these_methods_keep_the_old_inventory() -> None:
    ev = OpenClawMapper("solo").inventory({"groups": []}, {"id": "main"})
    p = ev.model_dump(mode="json")["payload"]
    assert p["model_runtimes"] == [] and p["sessions"] == []

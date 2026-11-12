"""Team gateway attribution (M5b): which person a session, run and tool call belongs to.

Frame shapes follow a live capture from the compose team gateway (OpenClaw 2026.11.3,
trusted-proxy auth): ids are made up, field names and nesting are as captured.
"""

from __future__ import annotations

import json
from typing import Any

from sg_advance.sensor.adapters.openclaw import OpenClawMapper
from sg_advance.sensor.adapters.openclaw_people import OpenClawPeople
from sg_advance.sensor.plugin_api import plugin_event

ALICE, BOB, CAROL = "p-alice", "p-bob", "p-carol"
MAIN = "agent:main:main"
DASH = "agent:main:dashboard:d49d"

USERS_LIST = {
    "profiles": [
        {"id": ALICE, "displayName": "alice", "emails": ["alice@corp.test"], "effectiveRole": "member"},
        {"id": BOB, "displayName": "bob", "emails": ["bob@corp.test"], "effectiveRole": "member"},
        {"id": "p-old", "displayName": "bob (old)", "emails": [], "mergedInto": BOB},
    ]
}


def actor(pid: str, label: str) -> dict[str, Any]:
    return {"type": "human", "id": pid, "identity": {"type": "profile", "id": pid}, "label": label}


def user_message(key: str, owner: str, sender: str, run: str, text: str = "hi") -> dict[str, Any]:
    return {
        "type": "event",
        "event": "session.message",
        "payload": {
            "sessionKey": key,
            "messageId": f"m-{run}",
            "createdActor": actor(owner, owner.removeprefix("p-")),
            "owner": {"actor": actor(owner, owner.removeprefix("p-"))},
            "participants": [],
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": text}],
                "__openclaw": {
                    "senderId": sender,
                    "senderName": sender.removeprefix("p-"),
                    "senderIdentity": {"type": "profile", "id": sender},
                    "idempotencyKey": f"{run}:user",
                },
            },
        },
    }


def tool_start(key: str, run: str, call: str, command: str = "whoami") -> dict[str, Any]:
    return {
        "type": "event",
        "event": "session.tool",
        "payload": {
            "runId": run,
            "sessionKey": key,
            "stream": "tool",
            "data": {"phase": "start", "name": "exec", "toolCallId": call, "args": {"command": command}},
        },
    }


def presence(pid: str, email: str, name: str) -> dict[str, Any]:
    user = {"id": pid, "identity": {"type": "profile", "id": pid}, "email": email, "name": name}
    return {
        "type": "event",
        "event": "presence",
        "payload": {"presence": [{"clientId": "ui"}, {"user": user}]},
    }


def test_tool_call_is_attributed_to_whoever_sent_the_run() -> None:
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_LIST)
    m.map_frame(user_message(DASH, BOB, BOB, "r-bob"))
    [call] = [e for e in m.map_frame(tool_start(DASH, "r-bob", "c1")) if e.kind.value == "tool.call"]
    assert call.principal.user_id == "bob@corp.test"
    assert call.principal.display_name == "bob"
    assert call.principal.groups == ("openclaw-role:member",)
    assert call.labels["openclaw.attribution"] == "sender"
    assert call.labels["openclaw.profile_id"] == BOB
    assert "openclaw.session_owner" not in call.labels


def test_two_people_on_one_gateway_stay_apart() -> None:
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_LIST)
    m.map_frame(user_message(MAIN, BOB, BOB, "r1"))
    m.map_frame(user_message(DASH, ALICE, ALICE, "r2"))
    a = m.map_frame(tool_start(DASH, "r2", "c2"))[-1]
    b = m.map_frame(tool_start(MAIN, "r1", "c1"))[-1]
    assert (a.principal.user_id, b.principal.user_id) == ("alice@corp.test", "bob@corp.test")


def test_writer_in_someone_elses_session_is_the_principal_and_owner_is_kept() -> None:
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_LIST)
    m.map_frame(user_message(MAIN, BOB, ALICE, "r3"))  # alice writes into bob's shared session
    call = m.map_frame(tool_start(MAIN, "r3", "c3"))[-1]
    assert call.principal.user_id == "alice@corp.test"
    assert call.labels["openclaw.session_owner"] == "bob@corp.test"


def test_session_owner_when_the_run_sender_is_unknown() -> None:
    """Sensor started mid-run, or an exec approval (no run id): the session owner is next best."""
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_LIST)
    m.people.learn_sessions({"sessions": [{"key": MAIN, "owner": {"actor": actor(BOB, "bob")}}]})
    call = m.map_frame(tool_start(MAIN, "r-unseen", "c4"))[-1]
    assert call.principal.user_id == "bob@corp.test"
    assert call.labels["openclaw.attribution"] == "session_owner"

    approval = {"id": "a1", "request": {"command": "rm -rf /tmp/x", "sessionKey": MAIN}}
    assert m.approval_request(approval)[-1].principal.user_id == "bob@corp.test"


def test_solo_gateway_keeps_the_sensor_user() -> None:
    m = OpenClawMapper("alice")
    call = m.map_frame(tool_start(MAIN, "r1", "c1"))[-1]
    assert call.principal.user_id == "alice"
    assert not any(k.startswith("openclaw.attribution") for k in call.labels)


def test_presence_supplies_email_for_someone_not_yet_listed() -> None:
    m = OpenClawMapper("team-gateway")
    m.map_frame(user_message(MAIN, CAROL, CAROL, "r5"))
    assert m.map_frame(tool_start(MAIN, "r5", "c5"))[-1].principal.user_id == "openclaw-profile:p-carol"
    m.map_frame(presence(CAROL, "carol@corp.test", "carol"))
    assert m.map_frame(tool_start(MAIN, "r5", "c6"))[-1].principal.user_id == "carol@corp.test"


def test_merged_profile_resolves_to_the_surviving_person() -> None:
    people = OpenClawPeople()
    people.learn_profiles(USERS_LIST)
    people.learn_sessions({"sessions": [{"key": MAIN, "createdActor": actor("p-old", "bob (old)")}]})
    assert people.attribute(MAIN, None, "x").principal["user_id"] == "bob@corp.test"


def test_non_human_actors_and_odd_frames_are_ignored() -> None:
    people = OpenClawPeople()
    people.observe(
        {
            "event": "sessions.changed",
            "payload": {"sessionKey": MAIN, "owner": {"actor": {"type": "agent", "id": "main"}}},
        }
    )
    people.observe(
        {"event": "session.message", "payload": {"sessionKey": MAIN, "message": {"role": "assistant"}}}
    )
    people.observe({"event": "presence", "payload": {"presence": [None, {"user": "nope"}]}})
    people.observe({"event": "session.message", "payload": "nope"})
    assert people.attribute(MAIN, "r1", "default").principal == {"user_id": "default"}


def test_plugin_judged_calls_use_what_the_websocket_side_learned() -> None:
    people = OpenClawPeople()
    people.learn_profiles(USERS_LIST)
    people.observe(user_message(DASH, ALICE, ALICE, "r9"))
    req = {"sessionKey": DASH, "runId": "r9", "toolCallId": "c9", "toolName": "exec", "params": {}}
    ev = plugin_event(req, user_id="team-gateway", hostname="gw", tool_plugins={}, people=people)
    assert ev.principal.user_id == "alice@corp.test"
    assert ev.labels["openclaw.attribution"] == "sender"
    assert ev.labels["sga_source"] == "openclaw_plugin"


def test_directory_survives_a_sensor_restart(tmp_path) -> None:
    """The plugin can judge calls before the WebSocket side reconnects (seen live, ~2 s)."""
    path = tmp_path / "openclaw-people.json"
    first = OpenClawPeople(state_path=path)
    first.learn_profiles(USERS_LIST)
    first.learn_sessions({"sessions": [{"key": MAIN, "owner": {"actor": actor(BOB, "bob")}}]})
    first.save()
    assert path.stat().st_mode & 0o077 == 0  # emails: owner-only

    again = OpenClawPeople(state_path=path)
    assert again.attribute(MAIN, "r-new", "team-gateway").principal["user_id"] == "bob@corp.test"
    path.write_text("{not json")
    assert OpenClawPeople(state_path=path).attribute(MAIN, None, "d").principal == {"user_id": "d"}


# ── delegation (sub-agents) ─────────────────────────────────────────────────
# Shapes from a live capture: secops asked the agent to spawn a sub-agent that ran `pwd`.

PARENT = "agent:main:dashboard:8a62"
CHILD = "agent:main:subagent:f65a"
AGENT_ACTOR = {"type": "agent", "id": "main"}


def child_created(child: str = CHILD, parent: str = PARENT, depth: int = 1) -> dict[str, Any]:
    return {
        "type": "event",
        "event": "sessions.changed",
        "payload": {
            "sessionKey": child,
            "reason": "create",
            "createdVia": "spawn",
            "spawnedBy": parent,
            "parentSessionKey": parent,
            "spawnDepth": depth,
            "controlOwnerSessionKey": parent,
            "createdActor": AGENT_ACTOR,
            "owner": {"actor": AGENT_ACTOR},
        },
    }


def spawn_result(parent: str, run: str, child: str) -> dict[str, Any]:
    text = json.dumps({"status": "accepted", "childSessionKey": child, "runId": "r-child"})
    return {
        "type": "event",
        "event": "session.tool",
        "payload": {
            "runId": run,
            "sessionKey": parent,
            "data": {
                "phase": "result",
                "name": "sessions_spawn",
                "toolCallId": "c-spawn",
                "result": {"content": [{"type": "text", "text": text}]},
            },
        },
    }


SECOPS = "p-secops"
USERS_WITH_SECOPS = {
    "profiles": [
        *USERS_LIST["profiles"],
        {"id": SECOPS, "displayName": "secops", "emails": ["secops@corp.test"], "effectiveRole": "security"},
    ]
}


def test_sub_agent_work_goes_back_to_the_person_who_delegated() -> None:
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_WITH_SECOPS)
    m.map_frame(user_message(PARENT, SECOPS, SECOPS, "r-parent"))
    m.map_frame(spawn_result(PARENT, "r-parent", CHILD))
    m.map_frame(child_created())
    evs = m.map_frame(tool_start(CHILD, "r-child", "c-pwd", "pwd"))
    start, call = evs
    assert start.payload.reason == "spawned"
    assert call.principal.user_id == "secops@corp.test"
    assert call.labels["openclaw.attribution"] == "delegation"
    assert (call.agent.parent_session_id, call.agent.root_session_id, call.agent.spawn_depth) == (
        PARENT,
        PARENT,
        1,
    )


def test_delegation_chain_of_two_hops_finds_the_root_person() -> None:
    m = OpenClawMapper("team-gateway")
    m.people.learn_profiles(USERS_LIST)
    m.map_frame(user_message(DASH, ALICE, ALICE, "r-a"))
    m.map_frame(child_created(CHILD, DASH, 1))
    grandchild = "agent:main:subagent:gc"
    m.map_frame(child_created(grandchild, CHILD, 2))  # no spawn result seen: falls back to the parent
    call = m.map_frame(tool_start(grandchild, "r-gc", "c-gc"))[-1]
    assert call.principal.user_id == "alice@corp.test"
    assert call.labels["openclaw.attribution"] == "delegation"
    assert (call.agent.parent_session_id, call.agent.root_session_id, call.agent.spawn_depth) == (
        CHILD,
        DASH,
        2,
    )


def test_ui_sessions_with_a_parent_key_are_not_delegation() -> None:
    """A conversation a person opens has parentSessionKey=agent:main:main but createdVia=operator."""
    people = OpenClawPeople()
    people.observe(
        {
            "event": "sessions.changed",
            "payload": {
                "sessionKey": DASH,
                "createdVia": "operator",
                "parentSessionKey": MAIN,
                "spawnDepth": 0,
            },
        }
    )
    assert people.lineage(DASH) == {}


def test_lineage_loops_never_hang() -> None:
    people = OpenClawPeople()
    people.parent.update({"a": "b", "b": "a"})
    assert people.lineage("a")["root_session_id"] in ("a", "b")
    assert people.attribute("a", None, "default").principal == {"user_id": "default"}


def test_plugin_judged_sub_agent_calls_carry_the_chain(tmp_path) -> None:
    path = tmp_path / "people.json"
    people = OpenClawPeople(state_path=path)
    people.learn_profiles(USERS_LIST)
    people.observe(user_message(DASH, BOB, BOB, "r-b"))
    people.observe(spawn_result(DASH, "r-b", CHILD))
    people.observe(child_created(CHILD, DASH, 1))
    people.save()
    restarted = OpenClawPeople(state_path=path)  # runs are not persisted; the chain and owners are
    req = {"sessionKey": CHILD, "runId": "r-child", "toolCallId": "c1", "toolName": "exec", "params": {}}
    ev = plugin_event(req, user_id="team-gateway", hostname="gw", tool_plugins={}, people=people)
    assert ev.principal.user_id == "bob@corp.test" and ev.agent.parent_session_id == DASH
    assert restarted.lineage(CHILD)["parent_session_id"] == DASH

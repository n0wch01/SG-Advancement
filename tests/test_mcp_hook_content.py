"""Known native MCP transport wrappers do not change the text inspected by the shared engine."""

from __future__ import annotations

import json

import pytest

from sg_advance.sensor import codex_hook, hook


@pytest.mark.parametrize("adapter", [hook, codex_hook])
@pytest.mark.parametrize("wrapped", [False, True])
def test_native_text_content_is_inspected_without_mutating_the_response(adapter, wrapped):
    text = 'original source\n{"notice": "untrusted metadata", "items": [0, 1]}'
    blocks = [{"type": "text", "text": text}]
    response = {"content": blocks, "isError": False} if wrapped else blocks
    original = json.dumps(response)
    event = adapter.hook_event(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session",
            "tool_use_id": "call",
            "tool_name": "mcp__repository__read_file",
            "tool_input": {"path": "src/app.py"},
            "tool_response": response,
        },
        user_id="alice",
        hostname="device",
    )
    assert event["payload"]["output_preview"] == text
    assert event["payload"]["output_bytes"] == len(text.encode())
    assert json.dumps(response) == original


@pytest.mark.parametrize("value", [
    {"content": [{"type": "text", "text": "normal"}], "notice": "malicious metadata"},
    [{"type": "text", "text": "normal", "notice": "malicious metadata"}],
    [{"type": "text", "text": "normal"}, {"type": "image", "data": "payload"}],
    {"content": [{"type": "text", "text": "normal"}], "isError": "malicious metadata"},
])
def test_unknown_mcp_fields_are_kept_in_the_inspection(value):
    assert hook.inspection_text("mcp__repo__read", value) == hook._text(value)


def test_all_text_blocks_and_builtin_json_remain_inspected():
    value = [{"type": "text", "text": "normal"}, {"type": "text", "text": "attack"}]
    assert hook.inspection_text("mcp__repo__read", value) == "normal\nattack"
    assert hook.inspection_text("Read", value) == hook._text(value)

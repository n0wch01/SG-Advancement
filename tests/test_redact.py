from __future__ import annotations

import pytest

from agent_sentinel.redact import redact_event, redact_text
from agent_sentinel.schema import AgentEvent


@pytest.mark.parametrize(
    ("text", "secret", "label"),
    [
        ("key AKIAABCDEFGHIJKLMNOP here", "AKIAABCDEFGHIJKLMNOP", "aws-access-key"),
        (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
            "abcdefghijklmnopqrstuvwxyz012345",
            "bearer",
        ),
        ("OPENAI=sk-proj-abcdefghijklmnopqrstuvwx", "sk-proj-abcdefghijklmnopqrstuvwx", "api-key"),
        ("ghp_" + "a" * 36, "ghp_" + "a" * 36, "github-token"),
        ('{"api_key": "s3cr3tvalue"}', "s3cr3tvalue", "secret"),
        ("password=hunter22", "hunter22", "secret"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "MIIabc", "private-key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz (truncated", "b3BlbnNz", "private-key"),
    ],
)
def test_redact_text(text: str, secret: str, label: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert f"[REDACTED:{label}]" in out


def test_prefix_is_kept_and_plain_text_untouched() -> None:
    assert redact_text("password=hunter22") == "password=[REDACTED:secret]"
    assert redact_text("set your password in the vault") == "set your password in the vault"
    assert redact_text("[REDACTED:secret]") == "[REDACTED:secret]"


def test_redact_event_covers_nested_payload_and_raw() -> None:
    ev = AgentEvent.model_validate(
        {
            "ts": "2026-11-10T00:00:00Z",
            "endpoint": {"device_id": "d"},
            "principal": {"user_id": "u"},
            "agent": {"type": "claude_code", "session_id": "s"},
            "source": {"sensor": "claude_code_hook"},
            "payload": {
                "kind": "tool.call",
                "call_id": "c",
                "tool": "Bash",
                "arguments": {"env": ["X=1", "token=abcdef123456"]},
            },
            "raw": {"tool_input": {"command": "echo AKIAABCDEFGHIJKLMNOP"}},
        }
    )
    out = redact_event(ev)
    dumped = out.model_dump_json()
    assert "abcdef123456" not in dumped and "AKIAABCDEFGHIJKLMNOP" not in dumped
    assert out.event_id == ev.event_id
    assert "token=abcdef123456" in ev.model_dump_json()  # original untouched

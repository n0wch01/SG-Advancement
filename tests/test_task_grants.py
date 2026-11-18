"""Task signature domain separation and bounded MCP credential transport failures."""

from __future__ import annotations

import base64
import io
import json
import threading
import urllib.error
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sg_advance.policy import public_key_b64
from sg_advance.sensor import task_mcp
from sg_advance.task_grants import GrantError, TaskClaims, sign_task, verify_task


@pytest.fixture
def capability(tmp_path):
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    claims = TaskClaims(
        grant_id="grant",
        user_id="alice",
        device_id="device",
        binding_id="binding",
        agent_type="codex_cli",
        session_id="session",
        project_id="alpha",
        environment="development",
        agent_profile="reader",
        actions=("source.read",),
        paths=("src",),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        policy_version="a" * 64,
    )
    token = sign_task(claims, key)
    path = tmp_path / "task.grant"
    path.write_text(token)
    path.chmod(0o600)
    return key, claims, token, path


def test_task_signature_is_not_a_policy_signature_and_scope_cannot_be_modified(capability):
    key, claims, token, _ = capability
    assert verify_task(token, key.public_key()) == claims
    document = json.loads(base64.urlsafe_b64decode(token))
    document["signature"] = base64.b64encode(key.sign(b"sg-advance/policy-bundle/v1:" + b"a" * 64)).decode()
    replay = base64.urlsafe_b64encode(json.dumps(document).encode()).decode()
    with pytest.raises(GrantError):
        verify_task(replay, key.public_key())
    document = json.loads(base64.urlsafe_b64decode(token))
    document["claims"]["paths"] = ["tests"]
    tampered = base64.urlsafe_b64encode(json.dumps(document).encode()).decode()
    with pytest.raises(GrantError):
        verify_task(tampered, key.public_key())
    with pytest.raises(GrantError):
        verify_task(token, Ed25519PrivateKey.generate().public_key())


def test_mcp_transport_never_follows_redirect_with_task_capability(capability):
    key, _, token, path = capability
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.path)
            if self.path == "/gateway":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/elsewhere")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError):
            task_mcp.exchange(
                f"http://127.0.0.1:{server.server_port}/gateway",
                path,
                public_key_b64(key.public_key()),
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
        assert received == ["/gateway"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_mcp_transport_refuses_public_or_symlinked_capability_file(capability, tmp_path):
    key, _, _, path = capability
    public = public_key_b64(key.public_key())
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private regular"):
        task_mcp.exchange("http://127.0.0.1:1/mcp", path, public, {"id": 1})
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        task_mcp.exchange("http://127.0.0.1:1/mcp", link, public, {"id": 1})


def test_disconnected_transport_returns_error_without_offline_execution_or_credential_output(
    capability,
    monkeypatch,
    capsys,
):
    key, _, token, path = capability
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "src/app.py", "content": "never sent"},
        },
    }
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO((json.dumps(message) + "\n").encode())))
    assert (
        task_mcp.main(
            [
                "--gateway",
                "http://127.0.0.1:1/mcp",
                "--grant-file",
                str(path),
                "--public-key",
                public_key_b64(key.public_key()),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["id"] == 7 and "error" in result and "retry" in result["error"]["message"]
    assert token not in captured.out + captured.err and "never sent" not in captured.out

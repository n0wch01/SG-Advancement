"""The live lab only signals groups it created, including when a saved PID is stale."""

from __future__ import annotations

import json
import os
import runpy
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

LAB_PROCESS = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "cc_lab_process.py"))
pytestmark = pytest.mark.skipif(os.name != "posix", reason="the live lab targets POSIX")
SLEEP = [sys.executable, "-c", "import time; time.sleep(60)", "sga-server", "--port", "8765"]


def test_stopping_one_lab_preserves_another_with_the_same_command(tmp_path: Path) -> None:
    first, other = tmp_path / "first", tmp_path / "other"
    start, stop, running = (LAB_PROCESS[k] for k in ("start", "stop", "running"))
    try:
        start(first, "server", tmp_path, SLEEP)
        start(other, "server", tmp_path, SLEEP)
        assert running(first, "server") and running(other, "server")
        stop(first, "server")
        assert not running(first, "server")
        assert running(other, "server")
        stop(first, "server")
    finally:
        for lab in (first, other):
            stop(lab, "server")


def test_a_saved_pid_cannot_signal_an_unrelated_group(tmp_path: Path) -> None:
    unrelated = subprocess.Popen(SLEEP, start_new_session=True)
    try:
        state = {"pid": unrelated.pid, "owner": "0" * 48}
        (tmp_path / "server-process.json").write_text(json.dumps(state))
        with pytest.raises(RuntimeError, match="refusing to signal"):
            LAB_PROCESS["stop"](tmp_path, "server")
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_an_occupied_port_does_not_start_or_adopt_a_server(tmp_path: Path) -> None:
    with socket.socket() as unrelated:
        unrelated.bind(("127.0.0.1", 0))
        unrelated.listen()
        port = unrelated.getsockname()[1]
        with pytest.raises(OSError):
            LAB_PROCESS["start"](tmp_path, "server", tmp_path, SLEEP, port=port)
        assert unrelated.getsockname()[1] == port
        assert not (tmp_path / "server-process.json").exists()


def test_an_invalid_ownership_file_is_never_used_for_signals(tmp_path: Path) -> None:
    (tmp_path / "server-process.json").write_text('{"pid": 1, "owner": "invalid"}')
    with pytest.raises(RuntimeError, match="invalid process ownership"):
        LAB_PROCESS["stop"](tmp_path, "server")


def test_a_stale_socket_is_not_a_ready_daemon() -> None:
    with tempfile.TemporaryDirectory(prefix="sga-ready-", dir="/tmp") as temp:
        path = Path(temp) / "api.sock"
        with socket.socket(socket.AF_UNIX) as stale:
            stale.bind(str(path))
        assert path.exists() and not LAB_PROCESS["socket_ready"](path)
        path.unlink()
        with socket.socket(socket.AF_UNIX) as active:
            active.bind(str(path))
            active.listen()
            assert LAB_PROCESS["socket_ready"](path)

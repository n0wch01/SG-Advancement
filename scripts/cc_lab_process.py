"""Own the POSIX live lab's process groups without searching other applications by name."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


def state_path(lab: Path, name: str) -> Path:
    return lab / f"{name}-process.json"


def read_state(lab: Path, name: str) -> dict | None:
    try:
        doc = json.loads(state_path(lab, name).read_text())
        if int(doc["pid"]) <= 1 or len(doc["owner"]) != 48:
            return None
        return doc
    except (OSError, ValueError, KeyError, TypeError):
        return None


def owned(doc: dict) -> bool:
    pid = int(doc["pid"])
    try:
        if os.getpgid(pid) != pid:
            return False
    except ProcessLookupError:
        return False
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=False
    )
    return result.returncode == 0 and f"--owner {doc['owner']}" in result.stdout


def running(lab: Path, name: str) -> bool:
    doc = read_state(lab, name)
    return doc is not None and owned(doc)


def socket_ready(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(str(path))
        except OSError:
            return False
    return True


def start(lab: Path, name: str, cwd: Path, command: list[str], port: int | None = None) -> None:
    if not command:
        raise ValueError("a command is required")
    if running(lab, name):
        return
    if port is not None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    lab.mkdir(parents=True, exist_ok=True)
    owner = secrets.token_hex(24)
    supervisor = [
        sys.executable, str(Path(__file__).resolve()), "run", "--lab", str(lab), "--name", name,
        "--owner", owner, "--", *command,
    ]
    with (lab / f"{name}.log").open("ab") as log:
        process = subprocess.Popen(
            supervisor, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True
        )
    path = state_path(lab, name)
    path.write_text(json.dumps({"pid": process.pid, "owner": owner}) + "\n")
    path.chmod(0o600)
    time.sleep(0.05)
    if process.poll() is not None:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"{name} exited during startup; see {lab / (name + '.log')}")


def stop(lab: Path, name: str, grace: float = 5.0) -> None:
    path = state_path(lab, name)
    doc = read_state(lab, name)
    if doc is None:
        if path.exists():
            raise RuntimeError(f"invalid process ownership file: {path}")
        return
    if not owned(doc):
        status = subprocess.run(
            ["ps", "-p", str(doc["pid"]), "-o", "stat="], capture_output=True, text=True, check=False
        )
        if status.returncode == 1 or status.stdout.strip().startswith("Z"):
            path.unlink(missing_ok=True)
            return
        raise RuntimeError(f"refusing to signal an unowned or stale {name} process; inspect {path}")
    pid = int(doc["pid"])
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not owned(doc):
            path.unlink(missing_ok=True)
            return
        time.sleep(0.05)
    if owned(doc):
        os.killpg(pid, signal.SIGKILL)
    path.unlink(missing_ok=True)


def supervise(command: list[str]) -> int:
    child = subprocess.Popen(command)

    def terminate(signum: int, _frame: object) -> None:
        # Keep the owner alive until the child exits so a timeout can still verify group ownership.
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    return child.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("start", "status", "stop", "run", "ready"))
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--name", choices=("server", "daemon", "receiver"), required=True)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--port", type=int)
    parser.add_argument("--owner")
    parser.add_argument("--socket", type=Path)
    args, command = parser.parse_known_args()
    command = command[1:] if command[:1] == ["--"] else command
    try:
        if args.operation == "start":
            start(args.lab.resolve(), args.name, args.cwd.resolve(), command, args.port)
        elif args.operation == "status":
            return 0 if running(args.lab.resolve(), args.name) else 1
        elif args.operation == "stop":
            stop(args.lab.resolve(), args.name)
        elif args.operation == "ready":
            ready = args.socket and running(args.lab.resolve(), args.name) and socket_ready(args.socket)
            return 0 if ready else 1
        else:
            return supervise(command)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"cc_lab_process: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

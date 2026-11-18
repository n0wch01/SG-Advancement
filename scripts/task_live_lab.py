"""Owned, isolated resource lab; reuses the server, sensor, MCP gateway and existing CLI lab logins."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "data/task-live"
SENSOR_HOME = LAB / "sga-home"
PYTHON = ROOT / ".venv/bin/python"
SENSOR = ROOT / ".venv/bin/sga-sensor"
SERVER = "http://127.0.0.1:8775"
GATEWAY = "http://127.0.0.1:8776/mcp/repository"
PROJECT = "sga-task-" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:8]
CLAUDE_CONFIG = ROOT / "data/cc-live/config"
CODEX_CONFIG = ROOT / "data/codex-live/config"
DEVICE = "task-live-mac"
ROLES = {
    "developer": "developer",
    "qa": "qa",
    "soc": "soc",
    "security": "security_admin",
    "identity": "identity_admin",
}


def private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(value)
    path.chmod(0o600)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], cwd=ROOT, check=True, **kwargs)


def metadata() -> dict:
    return json.loads((LAB / "metadata.json").read_text())


def compose(*args, **kwargs):
    return run(
        [
            "docker",
            "compose",
            "--env-file",
            LAB / "server.env",
            "-p",
            PROJECT,
            "-f",
            ROOT / "compose.task-lab.yaml",
            *args,
        ],
        **kwargs,
    )


def process(action: str, *args, capture=False):
    return subprocess.run(
        [
            str(PYTHON),
            str(ROOT / "scripts/cc_lab_process.py"),
            action,
            "--lab",
            str(LAB),
            "--name",
            "daemon",
            *map(str, args),
        ],
        cwd=ROOT,
        text=True,
        capture_output=capture,
    )


def api(method: str, path: str, body=None, user: str | None = None):
    info = metadata()
    token = (
        info["admin_token"] if user is None else json.loads((LAB / "users.json").read_text())[user]["token"]
    )
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    req = urllib.request.Request(
        SERVER + path,
        method=method,
        headers=headers,
        data=json.dumps(body).encode() if body is not None else None,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"lab API {path} HTTP {exc.code}: {exc.read().decode()[:300]}") from None


def owned() -> None:
    ids = compose("ps", "-aq", capture_output=True, text=True).stdout.split()
    for container in ids:
        owner = run(
            ["docker", "inspect", "--format", '{{index .Config.Labels "sg-advance.task-owner"}}', container],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if owner != metadata()["owner"]:
            raise RuntimeError("refusing to operate a task-lab container with a different owner marker")


def fixtures() -> None:
    compose(
        "exec",
        "-T",
        "control-plane",
        "python",
        "-",
        text=True,
        input="""
from pathlib import Path
import json
root=Path('/data/resources')
for project in ('alpha','beta'):
    target=root/project
    if (target/'.initialized').exists():
        continue
    for directory in ('src','tests','docs','production'):
        (target/directory).mkdir(parents=True,exist_ok=True)
    (target/'src/app.py').write_text('original source\\n')
    (target/'tests/test_app.py').write_text('original test\\n')
    (target/'production/deploy.yaml').write_text('protected deployment\\n')
    (target/'.env').write_text('FAKE_TOKEN=not-a-real-secret\\n')
    (target/'README.md').write_text('Protected repository lab\\n')
    (target/'.initialized').touch()
print('Protected fixtures ready inside the container; existing files preserved.')
""",
    )


def seed() -> None:
    if (LAB / "users.json").exists():
        return
    for project in ("alpha", "beta"):
        api(
            "POST",
            "/v1/admin/rbac/projects",
            {"id": project, "name": project.title(), "workspace_root": f"/data/resources/{project}"},
        )
    users = {}
    for name, role in ROLES.items():
        uid = "lab-" + name
        api("POST", "/v1/admin/rbac/users", {"id": uid, "name": "Lab " + name})
        api(
            "POST",
            "/v1/admin/rbac/bindings",
            {
                "user_id": uid,
                "role_id": role,
                "project_id": None if name in {"identity", "security"} else "alpha",
            },
        )
        users[name] = api("POST", f"/v1/admin/rbac/users/{uid}/tokens", {"lifetime_seconds": 86400})
    private(LAB / "users.json", json.dumps(users))


def up() -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    LAB.chmod(0o700)
    (LAB / "workspace").mkdir(exist_ok=True)
    if not (LAB / "metadata.json").exists():
        info = {"owner": secrets.token_hex(20), "admin_token": secrets.token_urlsafe(32)}
        private(LAB / "metadata.json", json.dumps(info))
        private(
            LAB / "server.env",
            f"SGA_TASK_LAB_ADMIN_TOKEN={info['admin_token']}\nSGA_TASK_LAB_OWNER={info['owner']}\n",
        )
    owned()
    compose("up", "-d", "--build")
    for _ in range(60):
        try:
            api("GET", "/v1/admin/whoami")
            break
        except (OSError, RuntimeError):
            time.sleep(0.5)
    else:
        raise RuntimeError("task control plane did not start")
    fixtures()
    seed()
    if not (SENSOR_HOME / "credentials.json").exists():
        enrollment = api("POST", "/v1/admin/enrollment-tokens", {"label": "task-live"})["token"]
        env = dict(os.environ, SGA_ENROLL_TOKEN=enrollment)
        run(
            [SENSOR, "--home", SENSOR_HOME, "enroll", "--server", SERVER, "--device-id", DEVICE],
            env=env,
            stdout=subprocess.DEVNULL,
        )
    if process("status", capture=True).returncode != 0:
        result = process(
            "start",
            "--cwd",
            ROOT,
            "--port",
            "8776",
            "--",
            SENSOR,
            "--home",
            SENSOR_HOME,
            "run",
            "--user",
            "lab-claim",
            "--no-discovery",
            "--no-claude-code",
            "--mcp-gateway",
            "127.0.0.1:8776",
            "--mcp-server",
            f"repository={SERVER}/v1/resources/mcp",
            "--mcp-protected-resource",
            "repository",
            "--classifier",
            ROOT / "data/models/protectai-v2",
        )
        if result.returncode:
            raise RuntimeError("task sensor did not start")
    for _ in range(60):
        if process("ready", "--socket", SENSOR_HOME / "sga.sock", capture=True).returncode == 0:
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", 8776), timeout=0.2):
                break
        time.sleep(0.2)
    else:
        raise RuntimeError("task gateway did not become ready")
    print(f"Task control plane: {SERVER}/dashboard/ ; native workspace: {LAB / 'workspace'}")
    print(
        "Posture measures this isolated MCP gateway, not host hardware attestation. "
        "No production state changed."
    )


def install_hooks(restore: bool = False) -> None:
    home = ROOT / "data/cc-live/sga-home" if restore else SENSOR_HOME
    env = dict(os.environ, CLAUDE_CONFIG_DIR=str(CLAUDE_CONFIG))
    run([SENSOR, "--home", home, "claude-code", "install", "--user", "lab-claim"], env=env)
    run([SENSOR, "--home", home, "codex", "install", "--config-dir", CODEX_CONFIG, "--user", "lab-claim"])
    print("Review the exact Codex hook definitions before use; no hook-trust bypass is enabled.")


def slot(agent: str) -> str:
    value = secrets.token_hex(8)
    key = json.loads((SENSOR_HOME / "credentials.json").read_text())["policy_public_key"]
    grant_path = LAB / "grants" / (value + ".grant")
    server = {
        "command": str(PYTHON),
        "args": [
            "-m",
            "sg_advance.sensor.task_mcp",
            "--gateway",
            GATEWAY,
            "--grant-file",
            str(grant_path),
            "--public-key",
            key,
        ],
    }
    private(
        LAB / "slots" / (value + ".json"),
        json.dumps({"agent": agent, "session_id": None, "grant_file": str(grant_path)}),
    )
    private(
        LAB / "slots" / (value + "-mcp.json"), json.dumps({"mcpServers": {"protected_repository": server}})
    )
    if agent == "codex_cli":
        env = dict(os.environ, CODEX_HOME=str(CODEX_CONFIG))
        run(
            [
                "codex",
                "--no-daemon",
                "mcp",
                "add",
                "protected_repository",
                "--",
                server["command"],
                *server["args"],
            ],
            env=env,
            stdout=subprocess.DEVNULL,
        )
    print(value)
    return value


def prepare(args) -> None:
    path = LAB / "slots" / (args.slot + ".json")
    config = json.loads(path.read_text())
    if config["session_id"] not in {None, args.session}:
        raise RuntimeError("a launch slot cannot be reassigned to another native session")
    snapshot = api("GET", "/v1/admin/rbac")
    current_owner = next(d["owner_user_id"] for d in snapshot["devices"] if d["device_id"] == DEVICE)
    uid = "lab-" + args.user
    if current_owner != uid:
        api("PUT", f"/v1/admin/rbac/devices/{DEVICE}/owner", {"user_id": uid})
    sessions = api("GET", "/v1/admin/rbac/sessions", user=args.user)
    registered = next(
        (s for s in sessions if s["session_id"] == args.session and s["agent_type"] == config["agent"]), None
    )
    if registered is None:
        registered = api(
            "POST",
            "/v1/admin/rbac/sessions",
            {
                "device_id": DEVICE,
                "agent_type": config["agent"],
                "session_id": args.session,
                "project_id": "alpha",
            },
            user=args.user,
        )
    actions = ["source.read", "tests.write"] + (["source.write"] if args.user == "developer" else [])
    issued = api(
        "POST",
        "/v1/admin/tasks",
        {
            "binding_id": registered["binding_id"],
            "actions": actions,
            "paths": ["src", "tests", "docs", "README.md"],
            "agent_profile": "coder" if args.user == "developer" else "tester",
        },
        user=args.user,
    )
    private(Path(config["grant_file"]), issued["token"])
    config.update(session_id=args.session, user=args.user, grant_id=issued["grant_id"])
    private(path, json.dumps(config))
    print(
        json.dumps(
            {
                "grant_id": issued["grant_id"],
                "session_id": args.session,
                "actions": actions,
                "expires_at": issued["claims"]["expires_at"],
            }
        )
    )


def check() -> None:
    compose(
        "exec",
        "-T",
        "control-plane",
        "python",
        "-",
        text=True,
        input="""
from pathlib import Path
import hashlib,json
root=Path('/data/resources/alpha')
for name in ('src/app.py','tests/test_app.py','production/deploy.yaml','.env'):
    data=(root/name).read_bytes()
    print(json.dumps({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))
""",
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("up", "down", "install-hooks", "restore-hooks", "check"):
        sub.add_parser(name)
    create = sub.add_parser("slot")
    create.add_argument("agent", choices=["claude_code", "codex_cli"])
    prep = sub.add_parser("prepare")
    prep.add_argument("user", choices=["developer", "qa"])
    prep.add_argument("slot")
    prep.add_argument("session")
    latest = sub.add_parser("latest-session")
    latest.add_argument("agent", choices=["claude_code", "codex_cli"])
    args = p.parse_args()
    if args.action == "up":
        up()
    elif args.action == "down":
        owned()
        process("stop").check_returncode()
        compose("down")  # keep evidence and the owned Docker data volume
    elif args.action in {"install-hooks", "restore-hooks"}:
        install_hooks(args.action == "restore-hooks")
    elif args.action == "slot":
        slot(args.agent)
    elif args.action == "prepare":
        prepare(args)
    elif args.action == "check":
        check()
    elif args.action == "latest-session":
        rows = api("GET", f"/v1/admin/events?device_id={DEVICE}&kind=session.start&limit=100")
        print(next(e["agent"]["session_id"] for e in rows if e["agent"]["type"] == args.agent))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"task_live_lab: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

"""The Git gateway: real ``git fetch``/``git push`` to a protected project repository (2026-11-18).

Git smart HTTP over ``git upload-pack`` / ``git receive-pack --stateless-rpc`` (nothing to download). Every
request carries the device credential (added by the endpoint sensor's local Git proxy, never held by the
agent) and a task grant (``X-SGA-Task-Grant``). Fetch needs ``source.read``. A push is:

1. judged by the session's threat engine (``gateway_state``: history-based rules see earlier calls);
2. re-checked online right before it runs (``task_access.online_claims``: person, device, session,
   policy, posture, risk, remote blocks, revocation);
3. decided by the pinned pre-receive hook (``git_policy``: branches, deletions, force pushes, deploy refs,
   changed paths against the grant). One refused update refuses the whole push;
4. recorded per ref update with the grant and the outcome.

The repository is the project's workspace (``<workspace>/.git``); the file gateway cannot touch ``.git``
(hidden paths are refused). PR records and CI runs are the resource MCP tools ``create_pr`` / ``run_ci``.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..redact import redact_text
from ..task_grants import GrantError, TaskClaims
from . import audit_chain, resource_files
from .auth import DbSession
from .db import Device, Project
from .git_policy import WORK_PREFIXES
from .task_access import CurrentDevice, online_claims

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/resources/git", tags=["protected resources"])
MAX_BODY = 32 * 1024 * 1024
GIT_TIMEOUT = 120
WRITE_ACTIONS = ("source.write", "tests.write")
_hooks_lock = threading.Lock()


# ── repository and git processes ────────────────────────────────────────────


def git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """No system or user Git config: aliases, hooks or credential helpers on this host never apply."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    return env | (extra or {})


def repository(request: Request, db: Session, project_id: str) -> Path:
    project = db.get(Project, project_id)
    if project is None or project.disabled_at is not None or not project.workspace_root:
        raise HTTPException(404, "repository not found")
    try:
        root = resource_files.project_root(request.app.state.settings.resource_root, project.workspace_root)
    except GrantError:
        raise HTTPException(503, "protected resources are disabled for this project") from None
    gitdir = root / ".git"
    if gitdir.is_symlink() or not gitdir.is_dir():
        raise HTTPException(503, "repository not provisioned")
    return root


HOOK = (
    "#!{python}\n"
    "import os, sys\n"
    "if os.environ.get('SGA_HOOK_PROBE'):  # the server checks that this file really runs\n"
    "    print(os.environ['SGA_HOOK_PROBE'])\n"
    "    sys.exit(0)\n"
    "from sg_advance.server.git_policy import main\n"
    "sys.exit(main())\n"
)


def hooks_dir(request: Request) -> Path:
    """The pre-receive hook the server pins for every push (repository hooks are never used).

    Git skips a hook it cannot execute without failing the push, so a hook that does not run would
    accept everything. Before every push the hook is run directly with a nonce; if it does not answer,
    the push is refused (fail closed) and nothing reaches git."""
    with _hooks_lock:
        path = getattr(request.app.state, "git_hooks_dir", None)
        if path is None or not (Path(path) / "pre-receive").exists():
            parent = request.app.state.settings.resource_git_hooks_dir
            if parent is not None:
                Path(parent).mkdir(parents=True, exist_ok=True, mode=0o700)
            path = Path(tempfile.mkdtemp(prefix="sga-git-hooks-", dir=parent))
            hook = path / "pre-receive"
            hook.write_text(HOOK.format(python=sys.executable), encoding="utf-8")
            hook.chmod(stat.S_IRWXU)
            request.app.state.git_hooks_dir = path
    nonce = uuid4().hex
    try:
        probe = subprocess.run(
            [str(Path(path) / "pre-receive")], capture_output=True, text=True, timeout=30,
            env=git_env({"SGA_HOOK_PROBE": nonce}),
        )  # fmt: skip
        runs = probe.returncode == 0 and probe.stdout.strip() == nonce
    except (OSError, subprocess.SubprocessError):
        runs = False
    if not runs:
        raise HTTPException(503, "the push policy hook cannot run here; push refused (fail closed)")
    return Path(path)


def run_git(args: list[str], *, cwd: Path, stdin: bytes = b"", env: dict[str, str] | None = None) -> bytes:
    done = subprocess.run(
        ["git", *args], cwd=cwd, input=stdin, capture_output=True, timeout=GIT_TIMEOUT, env=git_env(env)
    )
    if done.returncode != 0 and not done.stdout:
        raise HTTPException(500, "git failed")
    return done.stdout


def pkt(line: str) -> bytes:
    data = line.encode()
    return f"{len(data) + 4:04x}".encode() + data


def ref_updates(body: bytes) -> list[str]:
    """``<old> <new> <ref>`` lines from a receive-pack request (pkt-lines before the pack)."""
    out, i = [], 0
    while i + 4 <= len(body):
        size = int(body[i : i + 4], 16)
        if size == 0:
            break
        if size < 4 or i + size > len(body):
            raise HTTPException(400, "malformed git request")
        line = body[i + 4 : i + size].split(b"\0", 1)[0].decode("utf-8", "replace").rstrip("\n")
        if line and not line.startswith("shallow "):
            out.append(line)
        i += size
    return out


async def read_body(request: Request) -> bytes:
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_BODY:
            raise HTTPException(413, "push too large for the gateway")
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(bytes(raw))) as f:
                data = f.read(MAX_BODY + 1)
        except OSError:
            raise HTTPException(400, "invalid gzip body") from None
        if len(data) > MAX_BODY:
            raise HTTPException(413, "push too large for the gateway")
        return data
    return bytes(raw)


# ── authorization and records ───────────────────────────────────────────────


def grant_for(
    request: Request, device: Device, project_id: str, action: str | None
) -> tuple[str, TaskClaims]:
    token = request.headers.get("x-sga-task-grant", "")
    claims = online_claims(request, token, device_id=device.device_id, action=action)
    if claims.project_id != project_id:
        raise HTTPException(403, "task authorization denied: project_outside_grant")
    return token, claims


def git_event_payload(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "tool.call",
        "call_id": uuid4().hex,
        "tool": tool,
        "provider": {"kind": "mcp", "mcp_server": "protected-repository"},
        "arguments": arguments,
    }


def denied(
    request: Request, db: Session, device: Device, token: str, exc: HTTPException, payload: dict
) -> None:
    from .resource_mcp import auth_failure

    auth_failure(request, db, device, token, str(exc.detail), payload, evidence="git was not run")


def threat_check(
    request: Request, db: Session, device: Device, claims: TaskClaims, payload: dict
) -> str | None:
    """The session's threat engine on the operation; the reason when it must not run."""
    from ..sensor.decision import approval_channel, point_response
    from .resource_mcp import POINT, judge_in_session, operation_event, record

    event = operation_event(device, claims, payload)
    verdict = judge_in_session(request, device, claims.session_id, event)
    response, enforcement = point_response(verdict, POINT, approval_channel(verdict, POINT))
    if response["decision"] != "allow":
        record(db, device, event, verdict.findings + verdict.enforcing_repeats, enforcement)
        return str(response.get("reason") or "blocked by threat policy")
    return None


def record_operation(
    db: Session, device: Device, claims: TaskClaims, payload: dict, *, allowed: bool, detail: dict
) -> None:
    from .resource_mcp import operation_event, record

    event = operation_event(device, claims, payload, authorized=allowed)
    audit_chain.append(
        db,
        "git_operation",
        event.event_id,
        {
            "actor": claims.user_id,
            "grant_id": claims.grant_id,
            "project_id": claims.project_id,
            "allowed": allowed,
            **detail,
        },
    )
    record(db, device, event, [])


# ── smart HTTP ──────────────────────────────────────────────────────────────

SERVICES = {"git-upload-pack": "source.read", "git-receive-pack": None}


def _advertise(request: Request, db: Session, device: Device, project_id: str, service: str) -> Response:
    if service not in SERVICES:
        raise HTTPException(403, "unsupported git service")
    root = repository(request, db, project_id)
    token, claims = grant_for(request, device, project_id, SERVICES[service])
    if service == "git-receive-pack" and not set(WRITE_ACTIONS) & set(claims.actions):
        raise HTTPException(403, "task authorization denied: no write action in the grant")
    refs = run_git([service.removeprefix("git-"), "--stateless-rpc", "--advertise-refs", "."], cwd=root)
    body = pkt(f"# service={service}\n") + b"0000" + refs
    return Response(
        body, media_type=f"application/x-{service}-advertisement", headers={"Cache-Control": "no-cache"}
    )


@router.get("/{project_id}.git/info/refs")
def info_refs(
    project_id: str, service: str, request: Request, device: CurrentDevice, db: DbSession
) -> Response:
    return _advertise(request, db, device, project_id, service)


@router.post("/{project_id}.git/git-upload-pack")
async def upload_pack(project_id: str, request: Request, device: CurrentDevice, db: DbSession) -> Response:
    import asyncio

    body = await read_body(request)

    def run() -> Response:
        root = repository(request, db, project_id)
        _, claims = grant_for(request, device, project_id, "source.read")
        out = run_git(["upload-pack", "--stateless-rpc", "."], cwd=root, stdin=body)
        record_operation(
            db,
            device,
            claims,
            git_event_payload("git_fetch", {"project": project_id}),
            allowed=True,
            detail={"operation": "fetch"},
        )
        return Response(
            out, media_type="application/x-git-upload-pack-result", headers={"Cache-Control": "no-cache"}
        )

    return await asyncio.to_thread(run)


@router.post("/{project_id}.git/git-receive-pack")
async def receive_pack(project_id: str, request: Request, device: CurrentDevice, db: DbSession) -> Response:
    import asyncio

    body = await read_body(request)
    return await asyncio.to_thread(_push, request, db, device, project_id, body)


def _push(request: Request, db: Session, device: Device, project_id: str, body: bytes) -> Response:
    root = repository(request, db, project_id)
    updates = ref_updates(body)
    if not updates:
        raise HTTPException(400, "no ref updates in the push")
    payload = git_event_payload("git_push", {"project": project_id, "updates": updates[:50]})
    token = request.headers.get("x-sga-task-grant", "")
    try:
        _, claims = grant_for(request, device, project_id, None)
        if not set(WRITE_ACTIONS) & set(claims.actions):
            raise HTTPException(403, "task authorization denied: no write action in the grant")
    except HTTPException as exc:
        denied(request, db, device, token, exc, payload)
        raise
    if reason := threat_check(request, db, device, claims, payload):
        raise HTTPException(403, reason)
    try:  # immediately before execution: the newest state, not the state at the first check
        grant_for(request, device, project_id, None)
    except HTTPException as exc:
        denied(request, db, device, token, exc, payload)
        raise
    try:
        hooks = hooks_dir(request)
    except HTTPException as exc:  # the policy hook would be skipped by git: nothing may be pushed
        record_operation(db, device, claims, payload, allowed=False,
                         detail={"operation": "push", "reason": str(exc.detail)})  # fmt: skip
        raise
    with tempfile.TemporaryDirectory(prefix="sga-push-") as tmp:
        report = Path(tmp) / "report.json"
        policy = json.dumps({"actions": sorted(claims.actions), "paths": list(claims.paths)})
        out = run_git(
            [
                "-c",
                f"core.hooksPath={hooks}",
                "-c",
                "receive.fsckObjects=true",
                "-c",
                "receive.denyDeletes=true",
                "-c",
                "receive.denyNonFastForwards=true",
                "-c",
                "receive.denyCurrentBranch=refuse",
                "receive-pack",
                "--stateless-rpc",
                ".",
            ],
            cwd=root,
            stdin=body,
            env={"SGA_PUSH_POLICY": policy, "SGA_PUSH_REPORT": str(report)},
        )
        ran = report.exists()
        decided = json.loads(report.read_text(encoding="utf-8")) if ran else []
    allowed = bool(decided) and all(u["allowed"] for u in decided)
    detail: dict[str, Any] = {"operation": "push", "updates": decided[:50]}
    if not ran:  # git ran but the hook left no report: what git did is not known from the hook
        log.error("git push to %s ran without a push policy report", project_id)
        detail["hook_report_missing"] = True
    record_operation(db, device, claims, payload, allowed=allowed, detail=detail)
    return Response(
        out, media_type="application/x-git-receive-pack-result", headers={"Cache-Control": "no-cache"}
    )


# ── PR records and CI (resource MCP tools) ──────────────────────────────────


def _branch_head(root: Path, branch: str) -> str:
    if not any(f"refs/heads/{branch}".startswith(p) for p in WORK_PREFIXES) or ".." in branch:
        raise GrantError("use a work branch: feature/, fix/ or test/")
    try:
        return (
            run_git(["rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"], cwd=root).decode().strip()
        )
    except HTTPException:
        raise GrantError(f"branch {branch} has not been pushed") from None


def create_pr(request: Request, db: Session, device: Device, claims: TaskClaims, args: dict) -> str:
    root = repository(request, db, claims.project_id)
    branch, title = str(args.get("branch") or ""), str(args.get("title") or "")[:200]
    head = _branch_head(root, branch)
    payload = git_event_payload("create_pr", {"branch": branch, "head": head, "title": title})
    record_operation(
        db,
        device,
        claims,
        payload,
        allowed=True,
        detail={"operation": "pull_request", "branch": branch, "head": head, "base": "main", "title": title},
    )
    return f"PR recorded: {branch} @ {head[:12]} → main"


def run_ci(request: Request, db: Session, device: Device, claims: TaskClaims, args: dict) -> tuple[str, bool]:
    settings = request.app.state.settings
    if not settings.resource_ci_command:
        raise GrantError("CI is not configured on this control plane")
    root = repository(request, db, claims.project_id)
    branch = str(args.get("branch") or "")
    head = _branch_head(root, branch)
    archive = run_git(["archive", "--format=tar", head], cwd=root)
    work = Path(tempfile.mkdtemp(prefix="sga-ci-"))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter="data")
        started = time.monotonic()
        try:
            done = subprocess.run(
                list(settings.resource_ci_command),
                cwd=work,
                capture_output=True,
                text=True,
                timeout=settings.resource_ci_timeout_seconds,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work), "LANG": "C"},
            )
            code, output = done.returncode, (done.stdout + done.stderr)
        except subprocess.TimeoutExpired:
            code, output = -1, f"CI timed out after {settings.resource_ci_timeout_seconds}s"
        seconds = round(time.monotonic() - started, 1)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    tail = redact_text(output[-2000:])
    payload = git_event_payload("run_ci", {"branch": branch, "head": head})
    record_operation(
        db,
        device,
        claims,
        payload,
        allowed=True,
        detail={"operation": "ci", "branch": branch, "head": head, "exit_code": code, "seconds": seconds},
    )
    status = "passed" if code == 0 else "failed"
    return f"CI {status} on {branch} @ {head[:12]} (exit {code}, {seconds}s)\n{tail}", code == 0

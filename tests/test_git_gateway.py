"""The Git gateway with the real git client (server/resource_git.py, git_policy.py; 2026-11-18).

A developer and QA each hold a task grant. What counts is the repository afterwards (its refs and files),
not a log line: a refused push leaves no branch, a refused path leaves the branch where it was."""

from __future__ import annotations

import dataclasses
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import select
from sqlalchemy.orm import Session

from sg_advance.server.db import AuditEntry
from test_task_resources import grant, resources  # noqa: F401  # resources is a fixture

GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}  # fmt: skip
PR_AND_CI = ["source.read", "source.write", "tests.write", "pr.create", "ci.run"]


def git(*args: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "user.name=Agent", "-c", "user.email=agent@corp.test", *args],
        cwd=cwd, capture_output=True, text=True, env=GIT_ENV, check=check, timeout=60,
    )  # fmt: skip


@pytest.fixture
def server(cp):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(cp.app, lifespan="off", log_level="warning"))
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(5)


@pytest.fixture
def repo(resources):  # noqa: F811
    root = resources["root"]
    git("init", "-q", "-b", "main", cwd=root)
    git("add", "-A", cwd=root)
    git("commit", "-q", "-m", "initial", cwd=root)
    return resources


def clone(server: str, r: dict, device: str, capability: dict, dest: Path) -> list[str]:
    """Clone with the device credential and the grant; the -c options are reused for pushes."""
    opts = ["-c", f"http.extraHeader=Authorization: {r[device]['Authorization']}",
            "-c", f"http.extraHeader=X-SGA-Task-Grant: {capability['token']}"]  # fmt: skip
    git(*opts, "clone", "-q", f"{server}/v1/resources/git/alpha.git", str(dest))
    return opts


def call(cp, headers: dict, capability: dict, name: str, **args) -> dict:
    """A resource MCP tool call with only the tool's own arguments."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    headers = {**headers, "X-SGA-Task-Grant": capability["token"]}
    response = cp.post("/v1/resources/mcp", headers=headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def commit(work: Path, path: str, text: str, message: str) -> None:
    (work / path).parent.mkdir(parents=True, exist_ok=True)
    (work / path).write_text(text)
    git("add", path, cwd=work)
    git("commit", "-q", "-m", message, cwd=work)


def fresh_state(cp) -> None:
    """Each push is one call for the session's rate rule (5 a minute). Tests of the push policy start a clean
    window so a refusal comes from the policy, not from the rate rule (tested on its own below)."""
    from sg_advance.server.gateway_state import SessionEngines

    cp.app.state.session_engines = SessionEngines()


def heads(root: Path) -> set[str]:
    return set(git("for-each-ref", "--format=%(refname)", "refs/heads", cwd=root).stdout.split())


def test_a_developer_pushes_a_work_branch_and_nothing_else(cp, server, repo, tmp_path):
    r = repo
    dev = grant(cp, r["dev"], r["dev_session"], PR_AND_CI)
    work = tmp_path / "dev"
    opts = clone(server, r, "dev_device", dev, work)
    git("switch", "-q", "-c", "feature/login", cwd=work)
    commit(work, "src/login.py", "def login(): ...\n", "add login")
    assert git(*opts, "push", "-q", "origin", "feature/login", cwd=work, check=False).returncode == 0
    assert "refs/heads/feature/login" in heads(r["root"])

    main_before = git("rev-parse", "main", cwd=r["root"]).stdout
    refused = {
        "protected main": ["push", "origin", "HEAD:main"],
        "deploy branch": ["push", "origin", "HEAD:refs/heads/deploy/prod"],
        "release tag": ["push", "origin", "HEAD:refs/tags/v1.0"],
        "unknown namespace": ["push", "origin", "HEAD:refs/heads/hotfix-now"],
        "branch deletion": ["push", "origin", ":refs/heads/feature/login"],
    }
    for name, args in refused.items():
        fresh_state(cp)
        out = git(*opts, *args, cwd=work, check=False)
        assert out.returncode != 0 and "403" not in out.stderr, name  # refused by the push policy itself
    assert git("rev-parse", "main", cwd=r["root"]).stdout == main_before
    assert heads(r["root"]) == {"refs/heads/main", "refs/heads/feature/login"}
    assert not git("tag", cwd=r["root"]).stdout

    # A path outside what the grant can change: the branch stays where it was.
    good = git("rev-parse", "refs/heads/feature/login", cwd=r["root"]).stdout
    for path in ("production/deploy.yaml", ".env", ".github/workflows/x.yml"):
        commit(work, path, "changed\n", f"touch {path}")
        fresh_state(cp)
        out = git(*opts, "push", "origin", "feature/login", cwd=work, check=False)
        assert out.returncode != 0 and "SG-Advance" in out.stderr, path
        git("reset", "-q", "--hard", "HEAD~1", cwd=work)
    assert git("rev-parse", "refs/heads/feature/login", cwd=r["root"]).stdout == good
    # A force push (rewriting what was accepted) is refused too.
    git("commit", "-q", "--amend", "-m", "rewritten", cwd=work)
    fresh_state(cp)
    assert git(*opts, "push", "-f", "origin", "feature/login", cwd=work, check=False).returncode != 0
    assert git("rev-parse", "refs/heads/feature/login", cwd=r["root"]).stdout == good


def test_qa_may_push_tests_but_not_source(cp, server, repo, tmp_path):
    r = repo
    qa = grant(cp, r["qa"], r["qa_session"], ["source.read", "tests.write", "ci.run"], agent_profile="tester")
    work = tmp_path / "qa"
    opts = clone(server, r, "qa_device", qa, work)
    git("switch", "-q", "-c", "test/edge-cases", cwd=work)
    commit(work, "src/app.py", "qa edited source\n", "source change")
    out = git(*opts, "push", "origin", "test/edge-cases", cwd=work, check=False)
    assert out.returncode != 0 and "source.write" in out.stderr
    assert "refs/heads/test/edge-cases" not in heads(r["root"])
    git("reset", "-q", "--hard", "HEAD~1", cwd=work)
    commit(work, "tests/test_edge.py", "def test_edge(): pass\n", "tests only")
    assert git(*opts, "push", "-q", "origin", "test/edge-cases", cwd=work, check=False).returncode == 0
    assert "refs/heads/test/edge-cases" in heads(r["root"])


def test_revocation_applies_to_the_next_push_before_git_runs(cp, server, repo, tmp_path):
    r = repo
    dev = grant(cp, r["dev"], r["dev_session"])
    work = tmp_path / "dev"
    opts = clone(server, r, "dev_device", dev, work)
    git("switch", "-q", "-c", "feature/late", cwd=work)
    commit(work, "src/late.py", "x = 1\n", "late")
    assert cp.delete(f"/v1/admin/tasks/{dev['grant_id']}", headers=r["dev"]).status_code == 200
    out = git(*opts, "push", "origin", "feature/late", cwd=work, check=False)
    assert out.returncode != 0 and "403" in out.stderr
    assert "refs/heads/feature/late" not in heads(r["root"])


def test_repository_hooks_are_never_used(cp, server, repo, tmp_path):
    """The gateway pins its own pre-receive hook: a hook planted in the repository is ignored."""
    r = repo
    planted = r["root"] / ".git" / "hooks" / "pre-receive"
    planted.write_text("#!/bin/sh\nexit 0\n")
    planted.chmod(0o755)
    dev = grant(cp, r["dev"], r["dev_session"])
    work = tmp_path / "dev"
    opts = clone(server, r, "dev_device", dev, work)
    commit(work, "src/app.py", "straight to main\n", "main")
    assert git(*opts, "push", "origin", "HEAD:main", cwd=work, check=False).returncode != 0
    assert git("show", "main:src/app.py", cwd=r["root"]).stdout == "original source\n"


def test_pr_record_and_ci_need_their_own_actions(cp, server, repo, tmp_path):
    r = repo
    dev = grant(cp, r["dev"], r["dev_session"], PR_AND_CI)
    work = tmp_path / "dev"
    opts = clone(server, r, "dev_device", dev, work)
    git("switch", "-q", "-c", "feature/pr", cwd=work)
    commit(work, "tests/test_ok.py", "def test_ok(): assert True\n", "test")
    git(*opts, "push", "-q", "origin", "feature/pr", cwd=work)

    pr = call(cp, r["dev_device"], dev, "create_pr", branch="feature/pr", title="Add test")
    assert not pr["isError"] and "PR recorded: feature/pr" in pr["content"][0]["text"]
    assert call(cp, r["dev_device"], dev, "create_pr", branch="feature/missing", title="x")["isError"]

    off = call(cp, r["dev_device"], dev, "run_ci", branch="feature/pr")
    assert off["isError"] and "not configured" in off["content"][0]["text"]  # CI runs only when configured
    check = "import pathlib, sys; sys.exit(0 if pathlib.Path('tests/test_ok.py').exists() else 3)"
    command = (sys.executable, "-c", check)
    cp.app.state.settings = dataclasses.replace(cp.app.state.settings, resource_ci_command=command)
    ran = call(cp, r["dev_device"], dev, "run_ci", branch="feature/pr")
    assert not ran["isError"] and ran["content"][0]["text"].startswith("CI passed on feature/pr")

    qa = grant(cp, r["qa"], r["qa_session"], ["source.read", "tests.write", "ci.run"], agent_profile="tester")
    denied = call(cp, r["qa_device"], qa, "create_pr", branch="feature/pr", title="QA cannot open PRs")
    assert denied["isError"] and "action_not_authorized" in denied["content"][0]["text"]
    assert not call(cp, r["qa_device"], qa, "run_ci", branch="feature/pr")["isError"]

    with Session(cp.app.state.db.engine) as db:
        ops = [a.doc or {} for a in db.scalars(select(AuditEntry).where(AuditEntry.kind == "git_operation"))]
    kinds = [(o.get("operation"), o.get("allowed")) for o in ops]
    assert ("push", True) in kinds and ("pull_request", True) in kinds and ("ci", True) in kinds


def test_the_session_rate_rule_applies_at_the_git_gateway(cp, server, repo, tmp_path):
    """Per-session state: the fifth push of a session within a minute is stopped before git runs."""
    r = repo
    dev = grant(cp, r["dev"], r["dev_session"])
    work = tmp_path / "dev"
    opts = clone(server, r, "dev_device", dev, work)
    git("switch", "-q", "-c", "feature/burst", cwd=work)
    results = []
    for i in range(5):
        commit(work, f"src/burst_{i}.py", f"x = {i}\n", f"burst {i}")
        results.append(git(*opts, "push", "origin", "feature/burst", cwd=work, check=False))
    assert [o.returncode == 0 for o in results] == [True, True, True, True, False]
    assert "403" in results[4].stderr
    remote = git("show", "--name-only", "--format=", "refs/heads/feature/burst", cwd=r["root"]).stdout
    assert "src/burst_3.py" in remote and "src/burst_4.py" not in remote


@pytest.fixture
def proxy(server, repo):
    """The sensor's loopback Git proxy with the developer device's credential (the agent never sees it)."""
    import asyncio

    from sg_advance.sensor.task_git import GitProxyAdapter

    token = repo["dev_device"]["Authorization"].removeprefix("Bearer ")
    adapter = GitProxyAdapter("127.0.0.1", 0, server, token)
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(adapter.start())
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    ready.wait(5)
    yield f"http://127.0.0.1:{adapter.port}", token
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


def test_the_agent_holds_only_the_task_grant(cp, proxy, repo, tmp_path):
    """git → credential helper (the grant from a private file) → sensor proxy (adds the device credential)
    → control plane. Nothing in the agent's git configuration or environment carries the device token."""
    import os

    url, device_token = proxy
    r = repo
    dev = grant(cp, r["dev"], r["dev_session"])
    grant_file = tmp_path / "grant"
    grant_file.write_text(dev["token"])
    os.chmod(grant_file, 0o600)
    helper = f"!{sys.executable} -m sg_advance.sensor.task_git credential --grant-file {grant_file}"
    opts = ["-c", f"credential.helper={helper}"]
    work = tmp_path / "agent"
    git(*opts, "clone", "-q", f"{url}/git/alpha.git", str(work))
    git(*opts, "switch", "-q", "-c", "feature/via-proxy", cwd=work)
    commit(work, "src/proxy.py", "via = 'proxy'\n", "via proxy")
    assert git(*opts, "push", "-q", "origin", "feature/via-proxy", cwd=work, check=False).returncode == 0
    assert "refs/heads/feature/via-proxy" in heads(r["root"])
    out = git(*opts, "push", "origin", "HEAD:main", cwd=work, check=False)
    assert out.returncode != 0 and "protected" in out.stderr  # the control plane's hook still decides
    assert device_token not in " ".join(opts) and device_token not in (work / ".git" / "config").read_text()
    # A grant file others can read is refused, so git gets no credential at all.
    os.chmod(grant_file, 0o644)
    bad = git(*opts, "-c", "credential.interactive=false", "ls-remote", f"{url}/git/alpha.git", check=False)
    assert bad.returncode != 0


def test_the_push_hook_fails_closed(tmp_path):
    """Without the server's policy (the hook run any other way) every push is refused."""
    import os

    env = {k: v for k, v in os.environ.items() if not k.startswith("SGA_PUSH")}
    hook = [sys.executable, "-m", "sg_advance.server.git_policy"]
    line = "0 1 refs/heads/feature/x\n"
    out = subprocess.run(hook, input=line, capture_output=True, text=True, env=env, timeout=30)
    assert out.returncode == 1 and "fail closed" in out.stderr


def test_ref_updates_are_read_from_the_push_request() -> None:
    from sg_advance.server.resource_git import pkt, ref_updates

    old, new = "0" * 40, "a" * 40
    body = pkt(f"{old} {new} refs/heads/feature/x\0report-status side-band-64k\n") + pkt(
        f"{new} {old} refs/heads/main\n"
    ) + b"0000PACK...."
    assert ref_updates(body) == [f"{old} {new} refs/heads/feature/x", f"{new} {old} refs/heads/main"]

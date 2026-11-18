"""Push policy at the Git gateway: what a task grant lets an agent push (2026-11-18, docs/git-gateway.md).

Run as the pre-receive hook that ``resource_git`` pins with ``core.hooksPath`` (the repository's own hooks
are never used). Git hands the hook every ref update; the new objects are visible in quarantine, so the
files a push changes can be read before anything is accepted. One refused update refuses the whole push.

The grant's scope arrives in ``SGA_PUSH_POLICY`` (actions and path prefixes, set by the server from the
verified grant, never by the client); the outcome is written to ``SGA_PUSH_REPORT`` for the server to
record. Rules:

- protected branches (``main``, ``master``), deletions and non-fast-forward updates: refused;
- deployment refs (``deploy/*``, ``release/*``, ``prod*``) and tags: need ``deploy.production``, which no
  task grant can carry in this stage, so refused for every agent;
- work branches (``feature/``, ``fix/``, ``test/``) only;
- every changed path must be a supported resource (``resource_files.permission_for``: no hidden files), the
  grant must hold the matching action (``src``/``docs`` → ``source.write``, ``tests`` → ``tests.write``)
  and the path must be inside the grant's paths.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from ..task_grants import GrantError, within
from .resource_files import permission_for

PROTECTED = frozenset({"refs/heads/main", "refs/heads/master"})
DEPLOY_PREFIXES = ("refs/heads/deploy/", "refs/heads/release/", "refs/heads/prod")
WORK_PREFIXES = ("refs/heads/feature/", "refs/heads/fix/", "refs/heads/test/")
MAX_FILES = 2000


@dataclass
class Update:
    ref: str
    old: str
    new: str
    allowed: bool = False
    reason: str = ""
    files: list[str] = field(default_factory=list)


def is_zero(sha: str) -> bool:
    return bool(sha) and set(sha) == {"0"}


class Repo:
    """Read-only questions to the repository the hook runs in (quarantine objects included)."""

    def __init__(self, run: Callable[..., str] | None = None) -> None:
        self.run = run or self._git

    @staticmethod
    def _git(*args: str) -> str:
        return subprocess.run(["git", *args], check=True, capture_output=True, text=True, timeout=30).stdout

    def is_ancestor(self, old: str, new: str) -> bool:
        try:
            self.run("merge-base", "--is-ancestor", old, new)
            return True
        except subprocess.CalledProcessError:
            return False

    def base_for_new_branch(self, new: str) -> str:
        """What a new branch is compared with: where it left a protected branch, else the empty tree."""
        for protected in sorted(PROTECTED):
            try:
                return self.run("merge-base", protected, new).strip()
            except subprocess.CalledProcessError:
                continue
        return self.run("hash-object", "-t", "tree", os.devnull).strip()  # the empty tree, any object format

    def changed_files(self, base: str, new: str) -> list[str]:
        out = self.run("diff", "--name-only", "--no-renames", "-z", base, new)
        return [p for p in out.split("\0") if p]


def decide(update: Update, actions: set[str], paths: tuple[str, ...], repo: Repo) -> Update:
    ref = update.ref
    if is_zero(update.new):
        update.reason = "branch deletion is not allowed"
    elif ref in PROTECTED:
        update.reason = f"{ref} is protected: open a PR from a work branch"
    elif ref.startswith("refs/tags/") or ref.startswith(DEPLOY_PREFIXES):
        update.reason = "production deployment needs deploy.production, which a task grant cannot carry"
    elif not ref.startswith(WORK_PREFIXES):
        update.reason = "push to a work branch: feature/, fix/ or test/"
    elif not is_zero(update.old) and not repo.is_ancestor(update.old, update.new):
        update.reason = "force push (non-fast-forward) is not allowed"
    else:
        base = update.old if not is_zero(update.old) else repo.base_for_new_branch(update.new)
        update.files = repo.changed_files(base, update.new)
        if len(update.files) > MAX_FILES:
            update.reason = f"too many changed files ({len(update.files)} > {MAX_FILES})"
            return update
        for path in update.files:
            try:
                needed = permission_for(path, write=True)
            except GrantError as e:
                update.reason = f"{path}: {e}"
                return update
            if needed not in actions:
                update.reason = f"{path}: the task grant does not include {needed}"
                return update
            if not any(within(path, prefix) for prefix in paths):
                update.reason = f"{path}: outside the task grant's paths"
                return update
        update.allowed = True
        update.reason = "within the task grant"
    return update


def evaluate(lines: list[str], policy: dict[str, Any], repo: Repo | None = None) -> list[Update]:
    repo = repo or Repo()
    actions = set(policy.get("actions") or ())
    paths = tuple(policy.get("paths") or ())
    updates = []
    for line in lines:
        parts = line.split()
        if len(parts) != 3:
            updates.append(Update(line[:200], "", "", False, "unreadable ref update"))
            continue
        old, new, ref = parts
        updates.append(decide(Update(ref, old, new), actions, paths, repo))
    return updates


def main() -> int:
    """pre-receive: refuse the push unless every update is allowed; report what was decided."""
    try:
        policy = json.loads(os.environ["SGA_PUSH_POLICY"])
        report_path = os.environ["SGA_PUSH_REPORT"]
    except (KeyError, ValueError):
        print("SG-Advance: push policy unavailable; refused (fail closed)", file=sys.stderr)
        return 1
    try:
        updates = evaluate([line for line in sys.stdin.read().splitlines() if line.strip()], policy)
    except Exception as e:  # noqa: BLE001  # any failure refuses the push
        print(f"SG-Advance: push check failed ({type(e).__name__}); refused", file=sys.stderr)
        updates = [Update("?", "", "", False, f"check failed: {type(e).__name__}")]
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump([asdict(u) for u in updates], f)
    for u in updates:
        if not u.allowed:
            print(f"SG-Advance: {u.ref}: refused: {u.reason}", file=sys.stderr)
    return 0 if updates and all(u.allowed for u in updates) else 1


if __name__ == "__main__":
    raise SystemExit(main())

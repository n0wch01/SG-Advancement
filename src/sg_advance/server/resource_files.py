"""Bounded repository file I/O. No shell, path traversal, symlink following or arbitrary roots."""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from uuid import uuid4

from ..task_grants import GrantError, relative_path

MAX_FILE_BYTES = 65536
NEW_FILE_MODE = 0o600  # new files: owner only (the server's workspace copy is not shared)


def permission_for(path: str, *, write: bool) -> str:
    path = relative_path(path)
    parts = path.split("/")
    if any(part.startswith(".") for part in parts):
        raise GrantError("hidden files and credentials are outside supported resources")
    if parts[0] not in {"src", "tests", "docs"} and path != "README.md":
        raise GrantError("resource type is not supported")
    return ("tests.write" if parts[0] == "tests" else "source.write") if write else "source.read"


@contextlib.contextmanager
def parent_fd(root: Path, path: str):
    if os.name != "posix":
        raise GrantError("protected file resources currently require POSIX")
    parts = relative_path(path).split("/")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if not root.is_absolute():
        raise GrantError("an absolute registered workspace is required")
    fd = os.open("/", flags)
    try:
        for component in (*root.parts[1:], *parts[:-1]):
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def read_file(root: Path, path: str) -> str:
    with parent_fd(root, path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GrantError("only regular files are supported")
            data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise GrantError("protected file exceeds inspection limit")
    return data.decode("utf-8")


def write_file(root: Path, path: str, content: str) -> None:
    data = content.encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise GrantError("protected file exceeds write limit")
    with parent_fd(root, path) as (parent, name):
        mode = NEW_FILE_MODE
        try:
            old = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(old.st_mode):
                raise GrantError("only regular files are supported")
            # Keep the file's permission bits (an executable test script stays executable), never the
            # special bits: a write through the gateway must not create or keep setuid/setgid/sticky files.
            mode = stat.S_IMODE(old.st_mode) & 0o777
        except FileNotFoundError:
            pass
        temporary = f".sga-write-{uuid4().hex}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), mode)  # exact bits, independent of the server process umask
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # Replacement never follows a target symlink or modifies a target's other hard links.
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent)


def project_root(allowed: Path | None, root: str) -> Path:
    path = Path(root)
    if (
        allowed is None
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or not path.resolve().is_relative_to(allowed.resolve())
        or path.resolve() == allowed.resolve()
    ):
        raise GrantError("registered workspace is unavailable or outside configured resource root")
    return path.resolve()

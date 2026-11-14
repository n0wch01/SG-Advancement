"""Follow-up scenario 2 (CLAUDE.md): running a file downloaded to a temp path (docs/downloaded-exec.md).

The sensor remembers what a shell command downloaded (path, the host it came from) and labels a later
shell command that runs that path, or something under it (a cloned repo's script):
``labels.sga_runs_downloaded = "<host> <path>"``. Whether the path is a temp path and the host external
is the signed rules' decision (``run-downloaded-file``). Read from the commands themselves; nothing the
agent says about the file is used.

Not seen: paths built from variables, files fetched by other programs (python, a browser), files
extracted from a downloaded archive, downloads before the sensor (re)started.
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timedelta
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

from ..schema import AgentEvent, EventKind
from .state import now_utc
from .tools import SHELL as SHELL_TOOLS

LABEL = "sga_runs_downloaded"
KEEP = timedelta(hours=24)
MAX = 2000

_URL = re.compile(r"""\b(?:https?|ftp)://[^\s'"|;&)<>]+""", re.I)
_SEGMENT = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")  # one command at a time; pipes stay inside a segment
_INTERPRETERS = (
    r"(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby|php"
    r"|pwsh|powershell(?:\.exe)?|source|\.|exec"
)


def _args(segment: str) -> list[str]:
    """Words of one command. Windows paths keep their backslashes (non-POSIX splitting)."""
    try:
        if "\\" in segment:
            return [w.strip("'\"") for w in shlex.split(segment, posix=False)]
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _url_name(url: str) -> str | None:
    name = PurePosixPath(urlsplit(url).path).name
    return name or None


def _join(directory: str | None, name: str) -> str:
    if not directory:
        return name
    sep = "\\" if "\\" in directory and "/" not in directory else "/"
    return directory.rstrip("/\\") + sep + name


def downloads_in(command: str) -> list[tuple[str, str]]:
    """(path, host) pairs a shell command downloads to. Relative paths are joined with a preceding
    ``cd <dir>`` in the same command when there is one."""
    out: list[tuple[str, str]] = []
    cwd: str | None = None
    for segment in _SEGMENT.split(command):
        argv = _args(segment)
        if not argv:
            continue
        head = PurePosixPath(argv[0]).name.lower()
        if head == "cd" and len(argv) > 1:
            cwd = argv[1]
            continue
        urls = _URL.findall(segment)
        if not urls:
            continue
        host = (urlsplit(urls[0]).hostname or "?").lower()
        paths: list[str] = []
        if head in ("curl", "curl.exe"):
            for i, a in enumerate(argv):
                if a in ("-o", "--output") and i + 1 < len(argv):
                    paths.append(argv[i + 1])
                elif a.startswith("--output="):
                    paths.append(a.split("=", 1)[1])
                elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                    paths.append(a[2:])
                elif a in ("-O", "--remote-name") and (name := _url_name(urls[0])):
                    paths.append(name)
        elif head in ("wget", "wget.exe"):
            prefix = None
            for i, a in enumerate(argv):
                if a in ("-O", "--output-document") and i + 1 < len(argv) and argv[i + 1] != "-":
                    paths.append(argv[i + 1])
                elif a.startswith("--output-document=") and a.split("=", 1)[1] != "-":
                    paths.append(a.split("=", 1)[1])
                elif a in ("-P", "--directory-prefix") and i + 1 < len(argv):
                    prefix = argv[i + 1]
            if not paths and "-O" not in argv and "-qO-" not in segment and (name := _url_name(urls[0])):
                paths.append(_join(prefix, name))
        elif head in ("iwr", "invoke-webrequest", "irm", "invoke-restmethod"):
            for i, a in enumerate(argv):
                if a.lower() == "-outfile" and i + 1 < len(argv):
                    paths.append(argv[i + 1])
        elif head == "git" and len(argv) > 2 and argv[1] == "clone":
            rest = [a for a in argv[2:] if not a.startswith("-")]
            if len(rest) >= 2:
                paths.append(rest[1])
            elif rest and (name := _url_name(rest[0])):
                paths.append(name.removesuffix(".git"))
        if re.search(r"\b(?:curl|wget)\b[^|]*>\s*(\S+)", segment):  # curl URL > file
            paths.append(re.search(r">\s*(\S+)", segment).group(1))  # type: ignore[union-attr]
        for p in paths:
            p = p.strip("'\"")
            if p and p != "-":
                is_abs = p.startswith(("/", "~", "$", "%")) or PureWindowsPath(p).is_absolute()
                out.append((p if is_abs else _join(cwd, p.removeprefix("./")), host))
    return out


def _runs(command: str, path: str) -> bool:
    """Whether a shell command runs ``path`` (or a file under it): directly, through an interpreter,
    or with PowerShell's call operator / Start-Process."""
    name = re.split(r"[\\/]", path)[-1]
    targets = [re.escape(path) + r"(?:[\\/][^\s'\"]*)?"]
    if len(name) >= 3:
        targets += [r"\./" + re.escape(name)]
    target = "(?:" + "|".join(targets) + ")"
    start = r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+)"
    forms = [
        start + r"(?:sudo\s+(?:-\S+\s+)*)?[\"']?" + target + r"[\"']?(?=\s|$|[;&|)])",
        start + r"(?:" + _INTERPRETERS + r")\s+(?:-\S+\s+)*[\"']?" + target,
        r"&\s*[\"']?" + target,
        r"\bstart-process\s+(?:-filepath\s+)?[\"']?" + target,
    ]
    if len(name) >= 3:  # interpreter + bare file name after cd
        forms.append(start + r"(?:" + _INTERPRETERS + r")\s+(?:-\S+\s+)*[\"']?" + re.escape(name) + r"\b")
    return any(re.search(f, command, re.I | re.M) for f in forms)


class DownloadTracker:
    def __init__(self) -> None:
        self.files: dict[str, tuple[str, datetime]] = {}  # path -> (host, when)

    def labels_for(self, event: AgentEvent) -> dict[str, str]:
        """Label a shell call that runs a downloaded file, then remember what this call downloads."""
        if event.kind is not EventKind.TOOL_CALL or getattr(event.payload, "tool", "") not in SHELL_TOOLS:
            return {}
        args = getattr(event.payload, "arguments", {}) or {}
        command = args.get("command") or args.get("cmd") or ""
        if isinstance(command, list):
            command = " ".join(str(c) for c in command)
        if not isinstance(command, str) or not command:
            return {}
        labels: dict[str, str] = {}
        cutoff = now_utc() - KEEP
        for path, (host, when) in list(self.files.items()):
            if when < cutoff:
                del self.files[path]
            elif not labels and _runs(command, path):
                labels = {LABEL: f"{host} {path}"[:500]}
        for path, host in downloads_in(command):
            self.files.pop(path, None)
            self.files[path] = (host, now_utc())
            while len(self.files) > MAX:
                self.files.pop(next(iter(self.files)))
            if not labels and _runs(command, path):  # downloaded and run in one command (curl -o x && sh x)
                labels = {LABEL: f"{host} {path}"[:500]}
        return labels

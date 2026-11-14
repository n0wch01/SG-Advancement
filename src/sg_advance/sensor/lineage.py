"""Data lineage for the phase 2 scenario (CLAUDE.md): protected data queried from the test DB, then sent
to an unapproved destination. Scope: the test DB's MCP tools, the agent's tool calls that carry data
out (shell, web fetch, MCP tools, file writes). Not general data-loss prevention (docs/lineage.md).

Where the link comes from, and why it can be trusted:

- **Source**: a signed rule tagged ``lineage:source`` (regex ``collect``) names the protected values in
  a test DB tool result. The bytes come from the DB through the enforcement point (MCP gateway, or the
  agent's own tool-result hook), not from the model. The sensor keeps only salted hashes of them, with
  where they came from (event, call, server, tool, column names). Nothing the agent writes about the data
  ("safe", "anonymised", a classification field) is read.
- **Sink**: every tool call's arguments are tokenised; a token whose hash is known links the call to
  the read(s) it carries data from. A file written with protected data is remembered by path, so a later
  ``curl -F f=@out.csv`` links too. The destination is read from the call itself (URL host, MCP server,
  file path), never from what the agent says it is.
- The sensor only labels the call (``labels.sga_*``); the signed rules decide by sensitivity and
  destination together. Volume is never used.

Limitations (docs/lineage.md): transformed data (base64, hashing, re-typing, summaries) no longer
matches; a shell command whose output goes to a file is not seen (only the agent's own file writes).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import unquote, urlsplit

from ..detect.engine import LINEAGE_SOURCE_TAG
from ..schema import AgentEvent, EventKind
from . import tools
from .state import now_utc

log = logging.getLogger(__name__)

SOURCE_TAG = LINEAGE_SOURCE_TAG
SINK_TAG = "lineage:sink"
PROTECTED = "protected"
# Labels the sensor owns: anything an adapter (or an agent) put there before is dropped.
LABELS = ("sga_data_class", "sga_lineage", "sga_lineage_sources", "sga_lineage_fields", "sga_lineage_via",
          "sga_destinations")  # fmt: skip

KEEP = timedelta(hours=24)
MAX_SOURCES = 1000
MAX_HASHES = 100_000
MAX_PATHS = 2000
SCAN_MAX = 1_000_000  # characters of a call's arguments that are tokenised
MIN_TOKEN = 4

FILE_WRITE_TOOLS = tools.FILE_WRITE
WEB_TOOLS = tools.WEB
SEARCH_TOOLS = tools.SEARCH
SHELL_TOOLS = tools.SHELL
LOCAL_TOOLS = tools.LOCAL

_DIGITS_ONLY = re.compile(r"[\d\s\-.()+]+")
_DIGIT_RUN = re.compile(r"\d[\d\-.]{6,}\d")
_TOKEN = re.compile(r"[\w.@+\-]{4,}")  # MIN_TOKEN
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:'\"@]+@)?([^/\s:'\"?#]+)", re.I)
_SCP = re.compile(r"\b(?:scp|rsync|sftp)\b[^|;&]*?\s(?:[\w.-]+@)?([\w.-]+\.[\w-]+|\d+\.\d+\.\d+\.\d+):", re.I)
_GH = re.compile(r"(?:^|[\s;&|(\"'])gh\s+(?:issue|pr|repo|api|release|gist|run|search)\b")
_HOST = r"([\w.-]+\.[\w-]+|\d+\.\d+\.\d+\.\d+)"
_SOCKET = re.compile(r"\b(?:nc|ncat|netcat|telnet|ssh)\s+(?:-\S+\s+)*(?:[\w.-]+@)?" + _HOST, re.I)


def _forms(value: str) -> set[str]:
    """Normalised forms a protected value is matched by: lower case, and digits only for numbers
    written with separators (010-1234-5678 = 01012345678)."""
    v = value.strip().lower()
    out = {v} if len(v) >= MIN_TOKEN else set()
    if _DIGITS_ONLY.fullmatch(v):
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 8:
            out.add(digits)
    return out


def _candidates(text: str) -> set[str]:
    text = unquote(text[:SCAN_MAX]).lower()
    out = {t.strip(".-") for t in _TOKEN.findall(text)}
    out |= {re.sub(r"\D", "", m) for m in _DIGIT_RUN.findall(text)}
    return {t for t in out if len(t) >= MIN_TOKEN}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def mcp_server_of(event: AgentEvent) -> str | None:
    p = event.payload
    server = getattr(getattr(p, "provider", None), "mcp_server", None)
    if server:
        return str(server)
    tool = getattr(p, "tool", "") or ""
    if tool.startswith("mcp__") and tool.count("__") >= 2:
        return tool.split("__")[1]
    return None


def destinations(event: AgentEvent) -> list[str]:
    """Where a tool call sends what is in its arguments, read from the call itself.

    ``mcp:<server>``, ``file:<path>``, a host name, ``search`` (a web search query leaves the company),
    ``local`` (a shell command with no network target found, read-only tools) or ``unknown``."""
    p = event.payload
    tool = getattr(p, "tool", "") or ""
    args: dict[str, Any] = getattr(p, "arguments", {}) or {}
    server = mcp_server_of(event)
    if server:
        return [f"mcp:{server}"]
    if tool in FILE_WRITE_TOOLS:
        path = args.get("file_path") or args.get("path") or args.get("notebook_path")
        return [f"file:{path}"] if path else ["unknown"]
    if tool in SEARCH_TOOLS:
        return ["search"]
    text = _text(args)
    hosts = {m.group(2).lower().rstrip(".") for m in _URL.finditer(text)}
    if tool in SHELL_TOOLS:
        if _GH.search(text):  # the GitHub CLI talks to github.com without a URL (issues, PRs: external input)
            hosts.add("github.com")
        hosts |= {m.group(1).lower() for m in _SCP.finditer(text)}
        hosts |= {m.group(1).lower() for m in _SOCKET.finditer(text)}
        return sorted(hosts) or ["local"]
    if tool in WEB_TOOLS:
        url = args.get("url")
        if isinstance(url, str) and (host := urlsplit(url).hostname):
            hosts.add(host.lower())
        return sorted(hosts) or ["unknown"]
    if tool in LOCAL_TOOLS:
        return ["local"]
    return sorted(hosts) or ["unknown"]


@dataclass
class Source:
    """One read of protected data: the event the console shows as the start of the flow."""

    event_id: str
    call_id: str
    session_id: str | None
    tool: str
    server: str | None
    fields: list[str]
    ts: str


@dataclass
class _State:
    salt: str = field(default_factory=lambda: secrets.token_hex(16))
    sources: dict[str, Source] = field(default_factory=dict)
    hashes: dict[str, list[str]] = field(default_factory=dict)  # salted hash -> source event ids
    paths: dict[str, list[str]] = field(default_factory=dict)  # file written with protected data -> sources


class LineageStore:
    """Salted hashes of protected values seen in test DB results, and the files they were written to.
    Persisted (0600) so the hook's degraded path (no daemon) still links. If the file exists but cannot
    be read, ``available`` is False and calls are labelled ``sga_lineage=unavailable`` (fail closed: the
    rules block transfers to unapproved destinations)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.available = True
        self.state = _State()
        if path is not None and path.exists():
            try:
                raw = json.loads(path.read_text())
                self.state = _State(
                    salt=str(raw["salt"]),
                    sources={k: Source(**v) for k, v in raw.get("sources", {}).items()},
                    hashes={k: list(v) for k, v in raw.get("hashes", {}).items()},
                    paths={k: list(v) for k, v in raw.get("paths", {}).items()},
                )
            except (OSError, ValueError, KeyError, TypeError) as e:
                log.warning("lineage store %s unreadable (%s): transfers are judged as unknown", path, e)
                self.available = False

    def _hash(self, form: str) -> str:
        return hashlib.sha256(f"{self.state.salt}\0{form}".encode()).hexdigest()[:32]

    # ── source ───────────────────────────────────────────────────────────────

    def register(self, event: AgentEvent, collected: list[tuple[str, str]]) -> Source | None:
        if not collected or not self.available:
            return None
        p = event.payload
        src = Source(
            event_id=event.event_id,
            call_id=str(getattr(p, "call_id", "")),
            session_id=event.agent.session_id,
            tool=str(getattr(p, "tool", "")),
            server=mcp_server_of(event),
            fields=sorted({f for f, _ in collected}),
            ts=event.ts.isoformat(),
        )
        self.state.sources[src.event_id] = src
        for _, value in collected:
            for form in _forms(value):
                ids = self.state.hashes.setdefault(self._hash(form), [])
                if src.event_id not in ids:
                    ids.append(src.event_id)
        self._prune()
        self.save()
        return src

    # ── sink ─────────────────────────────────────────────────────────────────

    def _linked(self, text: str) -> tuple[list[str], str]:
        ids: dict[str, None] = {}
        for token in _candidates(text):
            for sid in self.state.hashes.get(self._hash(token), ()):
                ids.setdefault(sid)
        if ids:
            return list(ids), "value"
        for path, sids in self.state.paths.items():
            name = PurePath(path).name
            named = len(name) >= 5 and re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text)
            if path in text or named:
                return list(sids), f"file:{path}"
        return [], ""

    def labels_for(self, event: AgentEvent) -> dict[str, str]:
        """Labels for a tool call: which protected reads it carries data from, and where it sends it.
        An MCP tool result is marked ``tracked`` (the source rules only judge what this store keeps)."""
        if event.kind is EventKind.TOOL_RESULT:
            return {"sga_lineage": "tracked"} if self.available and mcp_server_of(event) else {}
        if event.kind is not EventKind.TOOL_CALL:
            return {}
        if not self.available:
            return {"sga_lineage": "unavailable", "sga_destinations": ",".join(destinations(event))}
        args = getattr(event.payload, "arguments", {}) or {}
        sids, via = self._linked(_text(args))
        sids = [s for s in sids if s in self.state.sources]
        if not sids:
            return {}
        fields = sorted({f for s in sids for f in self.state.sources[s].fields})
        dests = destinations(event)
        if event.payload.tool in FILE_WRITE_TOOLS:  # type: ignore[union-attr]
            self._taint(dests, sids)
        return {
            "sga_data_class": PROTECTED,
            "sga_lineage_sources": ",".join(sids[:10]),
            "sga_lineage_fields": ",".join(fields)[:300],
            "sga_lineage_via": via[:300],
            "sga_destinations": ",".join(dests)[:500],
        }

    def _taint(self, dests: list[str], sids: list[str]) -> None:
        for d in dests:
            if d.startswith("file:"):
                path = d.removeprefix("file:")
                self.state.paths[path] = list(dict.fromkeys([*self.state.paths.get(path, []), *sids]))
        self._prune()
        self.save()

    def source_ids(self, labels: dict[str, str]) -> list[str]:
        return [s for s in (labels.get("sga_lineage_sources") or "").split(",") if s]

    def mask(self, text: str) -> str:
        """Replace known protected values in ``text`` before it leaves the endpoint (events only; what
        the agent sees is not changed here)."""
        if not self.state.hashes:
            return text

        def repl(m: re.Match[str]) -> str:
            token = m.group(0)
            known = any(self.state.hashes.get(self._hash(f)) for f in _forms(token.strip(".-")))
            return "[보호 데이터]" if known else token

        return _TOKEN.sub(repl, text)

    # ── housekeeping ─────────────────────────────────────────────────────────

    def _prune(self) -> None:
        cutoff = now_utc() - KEEP
        live = {k: v for k, v in self.state.sources.items() if datetime.fromisoformat(v.ts) >= cutoff}
        if len(live) > MAX_SOURCES:
            live = dict(sorted(live.items(), key=lambda kv: kv[1].ts)[-MAX_SOURCES:])
        self.state.sources = live
        self.state.hashes = {
            h: kept for h, ids in self.state.hashes.items() if (kept := [i for i in ids if i in live])
        }
        if len(self.state.hashes) > MAX_HASHES:  # oldest-registered first out (dicts keep insertion order)
            self.state.hashes = dict(list(self.state.hashes.items())[-MAX_HASHES:])
        self.state.paths = {
            p: kept for p, ids in self.state.paths.items() if (kept := [i for i in ids if i in live])
        }
        if len(self.state.paths) > MAX_PATHS:
            self.state.paths = dict(list(self.state.paths.items())[-MAX_PATHS:])

    def save(self) -> None:
        if self.path is None:
            return
        doc = {
            "salt": self.state.salt,
            "sources": {k: asdict(v) for k, v in self.state.sources.items()},
            "hashes": self.state.hashes,
            "paths": self.state.paths,
        }
        tmp: str | None = None
        try:
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".lineage-")
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError as e:
            log.warning("lineage store %s not saved: %s", self.path, e)
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)

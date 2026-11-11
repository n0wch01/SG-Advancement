"""Content digests that tie installed agent code to a signed, published package.

The control plane computes them from a package tarball it verified (npm registry signature +
Sigstore provenance, ``server/supply.py``); the sensor computes them from the installed files. Both
sides import this module, so the algorithm cannot drift.

A *component* is one unit we can vouch for: ``core`` (the agent itself) or ``plugin:<id>``. Its
digest is ``sha256`` over sorted ``"<relative path>\\0<sha256 of file>\\n"`` lines, so an added,
removed, renamed or edited file changes it. ``node_modules`` is left out: npm installs those
dependencies separately and they are not part of what the publisher signed for this package.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Written by OpenClaw's installer and removed once post-install finishes; not part of the code.
_IGNORED_FILES = frozenset({".openclaw-lifecycle-pending"})
_SKIP_DIRS = frozenset({"node_modules", ".git"})
OPENCLAW_EXTENSIONS = "dist/extensions"

ManifestStatus = Literal["approved", "trusted", "cooling", "revoked", "rejected"]


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(files: Iterable[tuple[str, str]]) -> str:
    """``files``: (relative posix path, sha256 hex) pairs, any order."""
    h = hashlib.sha256()
    for rel, digest in sorted(files):
        h.update(f"{rel}\0{digest}\n".encode())
    return h.hexdigest()


def _skipped(parts: tuple[str, ...]) -> bool:
    return any(p in _SKIP_DIRS for p in parts[:-1]) or parts[-1] in _IGNORED_FILES


def dir_files(root: Path, exclude: tuple[str, ...] = ()) -> Iterator[tuple[str, str]]:
    """(relative path, sha256) for every regular file under ``root``. ``exclude`` lists relative
    directory prefixes to leave out (e.g. ``dist/extensions`` when hashing the core)."""
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root).as_posix()
        if _skipped(tuple(rel.split("/"))) or any(rel == e or rel.startswith(e + "/") for e in exclude):
            continue
        yield rel, file_sha256(p.read_bytes())


def dir_digest(root: Path, exclude: tuple[str, ...] = ()) -> str:
    return tree_digest(dir_files(root, exclude))


def openclaw_components(root: Path) -> dict[str, str]:
    """Digests of an installed OpenClaw package: the core plus each bundled plugin."""
    out = {"core": dir_digest(root, exclude=(OPENCLAW_EXTENSIONS,))}
    ext = root / OPENCLAW_EXTENSIONS
    if ext.is_dir():
        for d in sorted(p for p in ext.iterdir() if p.is_dir()):
            out[f"plugin:{d.name}"] = dir_digest(d)
    return out


def tarball_components(data: bytes, layout: Literal["openclaw", "plugin"]) -> dict[str, str]:
    """Digests from an npm tarball (files live under ``package/``).

    ``openclaw``: the OpenClaw package (``core`` + bundled ``plugin:<id>`` for dist/extensions/<id>).
    ``plugin``: a standalone plugin package; the id comes from its ``openclaw.plugin.json``.
    """
    files: dict[str, str] = {}
    manifest_id: str | None = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if _skipped(tuple(rel.split("/"))):
                continue
            blob = tf.extractfile(m).read()  # type: ignore[union-attr]
            files[rel] = file_sha256(blob)
            if rel == "openclaw.plugin.json":
                manifest_id = json.loads(blob).get("id")
    if layout == "plugin":
        if not manifest_id:
            raise ValueError("plugin package has no openclaw.plugin.json id")
        return {f"plugin:{manifest_id}": tree_digest(files.items())}
    prefix = OPENCLAW_EXTENSIONS + "/"
    out = {"core": tree_digest((r, d) for r, d in files.items() if not r.startswith(prefix))}
    plugins: dict[str, list[tuple[str, str]]] = {}
    for rel, d in files.items():
        if rel.startswith(prefix):
            pid, _, sub = rel[len(prefix) :].partition("/")
            if sub:
                plugins.setdefault(pid, []).append((sub, d))
    for pid, pairs in sorted(plugins.items()):
        out[f"plugin:{pid}"] = tree_digest(pairs)
    return out


class Manifest(BaseModel):
    """Known-good digests of one published package version, as shipped in the policy bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package: str = Field(description='npm name, e.g. "openclaw" or "@openclaw/codex"; "local:<id>" for pins')
    version: str
    status: ManifestStatus
    components: dict[str, str] = Field(description='"core" / "plugin:<id>" -> tree digest')
    integrity: str | None = Field(default=None, description="npm dist.integrity the digests came from")
    published_at: datetime | None = None
    source_repo: str | None = Field(default=None, description="Repository named in the verified provenance")
    trusted_after: datetime | None = Field(default=None, description="End of the release cooldown")


def effective_status(
    approved: bool,
    revoked: bool,
    published_at: datetime | None,
    cooldown: timedelta,
    now: datetime | None = None,
) -> ManifestStatus:
    """approved/revoked are decisions; otherwise a verified release is trusted once it is old enough."""
    if revoked:
        return "revoked"
    if approved:
        return "approved"
    now = now or datetime.now(UTC)
    if published_at is not None and now - published_at >= cooldown:
        return "trusted"
    return "cooling"


def lookup(manifests: Iterable[Manifest | dict[str, Any]], component: str, digest: str) -> Manifest | None:
    """The manifest that vouches for this exact content, best status first."""
    rank = {"approved": 0, "trusted": 1, "cooling": 2, "revoked": 3, "rejected": 4}
    hits = []
    for m in manifests:
        man = m if isinstance(m, Manifest) else Manifest.model_validate(m)
        if man.components.get(component) == digest:
            hits.append(man)
    return min(hits, key=lambda m: rank[m.status]) if hits else None

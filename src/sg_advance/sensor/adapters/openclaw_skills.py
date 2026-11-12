"""Skill integrity (supply chain beyond plugins): installed skills vs. digests security approved.

A skill is instructions (``SKILL.md``) plus scripts the model may run, installed from ClawHub
(``openclaw-managed``), dropped into an agent workspace (``openclaw-workspace``), or shipped by a plugin
(``openclaw-extra``). ClawHavoc (2026) spread hundreds of malicious skills through ClawHub, and a name
says nothing about the bytes. So, like plugins (``openclaw_integrity``):

1. the sensor hashes each non-bundled skill directory (``integrity.dir_digest``);
2. compares it with skill manifests in the signed policy (``sga-server manifest skill <ref>``:
   component ``skill:<source>:<name>`` → digest, approved by the security team);
3. puts verified, still-approved skills in the ``openclaw_skills`` trusted set, which
   ``openclaw-skill-unapproved`` honours (``allow_trusted``);
4. marks an approved skill whose files changed as ``mismatch`` (``openclaw-skill-tampered``) and,
   when the rule says quarantine, disables it: ``openclaw config set skills.entries.<key>.enabled false``.

Bundled skills ship inside the agent itself and are covered by the core's integrity, so they are
not hashed here.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ...integrity import Manifest, dir_digest, lookup

log = logging.getLogger(__name__)

TRUSTED_SET = "openclaw_skills"
GOOD_TRUST = ("approved", "trusted")
UNCHECKED_SOURCES = ("openclaw-bundled",)
Digester = Callable[[Path], str]
SkillDisabler = Callable[[str], tuple[bool, str]]


def component(ref: str) -> str:
    return f"skill:{ref}"


def check_skills(
    skills: list[dict[str, Any]], manifests: list[Manifest], digest: Digester = dir_digest
) -> set[str]:
    """Fill ``digest`` / ``integrity`` / ``trust`` on skill dicts in place. Returns trusted refs."""
    trusted: set[str] = set()
    for sk in skills:
        ref, path = sk.get("ref"), sk.get("path")
        if not ref or sk.get("source") in UNCHECKED_SOURCES or not path:
            continue
        try:
            if not Path(path).is_dir():  # gateway on another host: its paths are not ours
                continue
            d = digest(Path(path))
        except OSError as e:  # gateway on another host, or not readable by the sensor
            log.debug("cannot hash skill %s at %s: %s", ref, path, e)
            continue
        sk["digest"] = d
        comp = component(ref)
        match = lookup(manifests, comp, d)
        if match is not None:
            sk["integrity"], sk["trust"] = "verified", match.status
            if match.status in GOOD_TRUST:
                trusted.add(ref)
        elif any(comp in m.components and m.status in GOOD_TRUST for m in manifests):
            sk["integrity"], sk["trust"] = "mismatch", "approved"  # approved before, the bytes changed
        else:
            sk["integrity"] = "unknown"
    return trusted


def cli_skill_disabler(openclaw: str = "openclaw") -> SkillDisabler:
    def run(skill_key: str) -> tuple[bool, str]:
        exe = shutil.which(openclaw) or openclaw
        args = [exe, "config", "set", f"skills.entries.{skill_key}.enabled", "false"]
        res = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
        return res.returncode == 0, (res.stderr or res.stdout).strip()[:200]

    return run

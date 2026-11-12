"""Policy layers (M9): base rules → common overrides → a group's stricter overrides.

- **base**: ``rules/*.yaml`` as reviewed in the repository.
- **common** (``scope="common"``): security changes the company-wide policy. Anything goes (turn a
  rule off, lower or raise its response, change an allowlist), and every change is logged.
- **group** (``scope=<group name>``): a team may only make its policy *stricter* than common:
  turn rules on, raise the response, narrow an allowlist. ``check`` refuses anything else, and
  ``apply_group`` merges stricter-only again at build time, so a group override written against an
  older common policy can never end up looser than the current one.

Fields a v1 override can set: ``enabled``, ``response``, ``allow`` (allowlist rules only).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from ..schema import ResponseAction

COMMON = "common"
RESPONSES = [a.value for a in ResponseAction]  # least to most disruptive


def response_rank(value: str) -> int:
    return RESPONSES.index(value)


@dataclass(frozen=True)
class Override:
    enabled: bool | None = None
    response: str | None = None
    allow: tuple[str, ...] | None = None

    def is_empty(self) -> bool:
        return self.enabled is None and self.response is None and self.allow is None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.enabled is not None:
            out["enabled"] = self.enabled
        if self.response is not None:
            out["response"] = self.response
        if self.allow is not None:
            out["allow"] = list(self.allow)
        return out


def narrower(entry: str, current: list[str]) -> bool:
    """``entry`` allows nothing ``current`` doesn't: listed as is, or a plain name one of its globs
    covers (``api.openai.com`` under ``*.openai.com``). Allowlists match case-insensitively."""
    e = entry.lower()
    if e in (c.lower() for c in current):
        return True
    return not any(ch in e for ch in "*?[") and any(fnmatchcase(e, c.lower()) for c in current)


def is_allowlist(rule: dict[str, Any]) -> bool:
    return (rule.get("match") or {}).get("type") == "allowlist"


def check(rule: dict[str, Any], scope: str, ov: Override) -> list[str]:
    """Problems with applying ``ov`` in ``scope`` on top of ``rule`` (the rule as the layer below
    has it: base + common for a group). Empty list: allowed."""
    errors: list[str] = []
    if ov.is_empty():
        errors.append("nothing to change: set enabled, response or allow")
    if ov.response is not None and ov.response not in RESPONSES:
        errors.append(f"unknown response {ov.response!r} (one of {', '.join(RESPONSES)})")
    if ov.allow is not None and not is_allowlist(rule):
        errors.append(f"{rule['id']} is not an allowlist rule: allow does not apply")
    if scope == COMMON or errors:
        return errors
    # A group: stricter only.
    if ov.enabled is False:
        errors.append("a group cannot turn a rule off (ask security to change the common policy)")
    if ov.response is not None and response_rank(ov.response) < response_rank(rule.get("response", "alert")):
        errors.append(f"a group cannot lower the response below the common {rule.get('response', 'alert')!r}")
    if ov.allow is not None:
        current = list((rule.get("match") or {}).get("allow") or [])
        extra = [a for a in ov.allow if not narrower(a, current)]
        if extra:
            errors.append(
                f"a group can only narrow the allowlist; not in the common list: {', '.join(extra)}"
            )
    return errors


def apply_common(rules: list[dict[str, Any]], overrides: dict[str, Override]) -> list[dict[str, Any]]:
    out = []
    for rule in rules:
        ov = overrides.get(rule["id"])
        if ov is None:
            out.append(rule)
            continue
        r = copy.deepcopy(rule)
        if ov.enabled is not None:
            r["enabled"] = ov.enabled
        if ov.response is not None:
            r["response"] = ov.response
        if ov.allow is not None and is_allowlist(r):
            r["match"]["allow"] = list(ov.allow)
        out.append(r)
    return out


def apply_group(rules: list[dict[str, Any]], overrides: dict[str, Override]) -> list[dict[str, Any]]:
    """Stricter-only merge, whatever the stored override says."""
    out = []
    for rule in rules:
        ov = overrides.get(rule["id"])
        if ov is None:
            out.append(rule)
            continue
        r = copy.deepcopy(rule)
        if ov.enabled:
            r["enabled"] = True
        current = r.get("response", "alert")
        if ov.response in RESPONSES and response_rank(ov.response) > response_rank(current):
            r["response"] = ov.response
        if ov.allow is not None and is_allowlist(r):
            current = list(r["match"].get("allow") or [])
            r["match"]["allow"] = [a for a in ov.allow if narrower(a, current)]
        out.append(r)
    return out

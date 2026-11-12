"""Streaming local detection engine.

``Engine.process(event)`` evaluates one AgentEvent against every enabled rule and returns a
``Verdict``: which rules hit, the strongest suggested response, and the findings to report.
Batch analysis is just ``Engine.replay(events)``, so blocking sensors (hooks, proxies) and
offline replays share one code path.

Hits vs findings: a rule that matches always produces a hit (and contributes to the verdict),
but with ``dedup: session`` only the first hit per rule/session/key becomes a Finding, so a
blocked exfiltration attempt is blocked every time without flooding the console.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any

from ..redact import redact_text
from ..schema import AgentEvent, Enforcement, EventKind, Finding, ResponseAction
from .fields import condition_holds, first, resolve, string_leaves
from .rules import (
    AllowlistMatch,
    InSetMatch,
    RateMatch,
    RegexMatch,
    RepeatMatch,
    Rule,
    RuleSet,
    SequenceMatch,
    SequenceStep,
)

# Live sets the sensor maintains for allowlist ``allow_trusted`` (name -> values).
TrustedSets = dict[str, set[str]]
EXCERPT_CONTEXT = 40
# Campaign indicators (M11): findings of rules tagged ``campaign`` carry the matched value(s) in
# ``labels[INDICATOR]`` (normalised, newline-separated) so the control plane can tell when the same
# thing reaches several people (server/campaigns.py).
CAMPAIGN_TAG = "campaign"
INDICATOR = "indicator"
INDICATOR_MAX = 200
_ACTION_RANK = {a: i for i, a in enumerate(ResponseAction)}


@dataclass(frozen=True)
class Hit:
    rule: Rule
    key: str
    explanation: str
    evidence_event_ids: tuple[str, ...]
    reported: bool = True  # False when suppressed by dedup


@dataclass
class Verdict:
    event: AgentEvent
    hits: list[Hit] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def action(self) -> ResponseAction:
        return max(
            (h.rule.response for h in self.hits), key=_ACTION_RANK.__getitem__, default=ResponseAction.ALLOW
        )

    @property
    def rule_ids(self) -> list[str]:
        return [h.rule.id for h in self.hits]


@dataclass(frozen=True)
class _RawHit:
    key: str
    explanation: str
    evidence_event_ids: tuple[str, ...]
    values: tuple[str, ...] = ()  # the matched values themselves (campaign indicators)


def indicator_of(values: Iterable[str]) -> str | None:
    """Normalised (lower case, single spaces, redacted, capped), sorted, newline-separated."""
    out = sorted({redact_text(" ".join(v.lower().split()))[:INDICATOR_MAX] for v in values} - {""})
    return "\n".join(out) or None


def _session_key(doc: dict[str, Any]) -> tuple[str, str]:
    return (first(doc, "endpoint.device_id"), first(doc, "agent.session_id"))


def _excerpt(text: str, start: int, end: int) -> str:
    """Matched span wrapped in «», with some context; redacted (it ends up in the Finding)."""
    lo, hi = max(0, start - EXCERPT_CONTEXT), min(len(text), end + EXCERPT_CONTEXT)
    parts = (
        "…" if lo else "",
        text[lo:start],
        "«",
        text[start:end],
        "»",
        text[end:hi],
        "…" if hi < len(text) else "",
    )
    return redact_text("".join(parts).replace("\n", "\\n"))


def _search(doc: dict[str, Any], spec: RegexMatch | SequenceStep) -> tuple[str, str] | None:
    """Return (explanation, matched text) of the first regex hit, or None."""
    cre = spec.compiled()
    if cre is None:
        return "", ""
    for path in spec.fields:
        for value in resolve(doc, path):
            for text in string_leaves(value):
                m = cre.search(text)
                if m:
                    return f"{path}: {_excerpt(text, m.start(), m.end())}", m.group(0)
    return None


# ── matchers ────────────────────────────────────────────────────────────────


class _RegexMatcher:
    def __init__(self, spec: RegexMatch) -> None:
        self.spec = spec

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        hit = _search(doc, self.spec)
        return _RawHit("", hit[0], (event.event_id,), (hit[1],)) if hit is not None else None


class _AllowlistMatcher:
    def __init__(self, spec: AllowlistMatch, trusted: TrustedSets | None = None) -> None:
        self.spec = spec
        self.allow = [a.lower() for a in spec.allow] if spec.ignore_case else list(spec.allow)
        self.trusted = trusted if trusted is not None else {}

    def _allowed(self, value: str) -> bool:
        v = value.lower() if self.spec.ignore_case else value
        if self.spec.allow_trusted and v in {
            t.lower() if self.spec.ignore_case else t for t in self.trusted.get(self.spec.allow_trusted, ())
        }:
            return True
        return any(fnmatchcase(v, pat) for pat in self.allow)

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        values = sorted({str(v) for v in resolve(doc, self.spec.field) if not isinstance(v, dict | list)})
        offending = [v for v in values if not self._allowed(v)]
        if not offending:
            return None
        why = f"{self.spec.field} not in allowlist: {', '.join(redact_text(v) for v in offending)}"
        return _RawHit(",".join(offending), why, (event.event_id,), tuple(offending))


class _InSetMatcher:
    def __init__(self, spec: InSetMatch, trusted: TrustedSets | None = None) -> None:
        self.spec = spec
        self.trusted = trusted if trusted is not None else {}

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        members = self.trusted.get(self.spec.set) or set()
        if not members:
            return None
        for path in self.spec.fields:
            for v in resolve(doc, path):
                if isinstance(v, str) and v in members:
                    why = f"{path} is in {self.spec.set}: {redact_text(v)}"
                    return _RawHit(v, why, (event.event_id,), (v,))
        return None


class _RateMatcher:
    def __init__(self, spec: RateMatch) -> None:
        self.spec = spec
        self.windows: dict[tuple[str, ...], deque[tuple[datetime, str]]] = {}

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        group = tuple(first(doc, p) for p in self.spec.group_by)
        window = self.windows.setdefault(group, deque())
        window.append((event.ts, event.event_id))
        while window and (event.ts - window[0][0]).total_seconds() > self.spec.window_seconds:
            window.popleft()
        if len(window) < self.spec.threshold:
            return None
        why = (
            f"{len(window)} events within {self.spec.window_seconds:g}s "
            f"(threshold {self.spec.threshold}) for {'/'.join(group)}"
        )
        return _RawHit("/".join(group), why, tuple(i for _, i in window))


class _RepeatMatcher:
    def __init__(self, spec: RepeatMatch) -> None:
        self.spec = spec
        # group -> (signature, run length, last `threshold` event ids)
        self.state: dict[tuple[str, ...], tuple[str, int, list[str]]] = {}

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        group = tuple(first(doc, p) for p in self.spec.group_by)
        sig = json.dumps([resolve(doc, p) for p in self.spec.same], sort_keys=True, ensure_ascii=False)
        last = self.state.get(group)
        if last and last[0] == sig:
            count, ids = last[1] + 1, (last[2] + [event.event_id])[-self.spec.threshold :]
        else:
            count, ids = 1, [event.event_id]
        self.state[group] = (sig, count, ids)
        if count < self.spec.threshold:
            return None
        why = f"{count} consecutive identical calls ({', '.join(self.spec.same)}) for {'/'.join(group)}"
        return _RawHit("/".join(group), why, tuple(ids))


@dataclass
class _SeqProgress:
    next_step: int
    started: datetime
    event_ids: list[str]
    notes: list[str]
    first_session: str = ""


class _SequenceMatcher:
    def __init__(self, spec: SequenceMatch) -> None:
        self.spec = spec
        self.progress: dict[tuple[str, str], _SeqProgress] = {}

    def _step_hit(self, i: int, doc: dict[str, Any]) -> str | None:
        step = self.spec.steps[i]
        if not condition_holds(doc, step.when):
            return None
        hit = _search(doc, step)
        if hit is None:
            return None
        why = hit[0]
        label = step.name or f"step{i + 1}"
        return f"{label}({first(doc, 'payload.kind')}{': ' + why if why else ''})"

    def _key(self, doc: dict[str, Any]) -> tuple[str, str]:
        if self.spec.scope == "delegation":  # the tree's top session; a root session is its own top
            return (
                first(doc, "endpoint.device_id"),
                first(doc, "agent.root_session_id") or first(doc, "agent.session_id"),
            )
        return _session_key(doc)

    def check(self, event: AgentEvent, doc: dict[str, Any]) -> _RawHit | None:
        key = self._key(doc)
        session = first(doc, "agent.session_id")
        p = self.progress.get(key)
        if p and (event.ts - p.started).total_seconds() > self.spec.within_seconds:
            p = None
            del self.progress[key]
        if p is not None:
            note = self._step_hit(p.next_step, doc)
            last = p.next_step == len(self.spec.steps) - 1
            if note is not None and last and self.spec.distinct_sessions and session == p.first_session:
                note = None  # same session: the session-scoped rules already cover it
            if note is not None and self.spec.distinct_sessions:
                note = f"{note} @{session}"
            if note is not None:
                p.next_step += 1
                p.event_ids.append(event.event_id)
                p.notes.append(note)
                if p.next_step == len(self.spec.steps):
                    del self.progress[key]
                    return _RawHit("", " → ".join(p.notes), tuple(p.event_ids))
                return None
            if p.next_step > 1:
                return None
        # (Re)start: a fresh first step also refreshes a sequence stuck after step 1.
        note = self._step_hit(0, doc)
        if note is not None:
            if self.spec.distinct_sessions:
                note = f"{note} @{session}"
            self.progress[key] = _SeqProgress(1, event.ts, [event.event_id], [note], session)
        return None

    def forget_session(self, key: tuple[str, str]) -> None:
        self.progress.pop(key, None)


_MATCHERS = {
    "regex": _RegexMatcher,
    "allowlist": _AllowlistMatcher,
    "rate": _RateMatcher,
    "repeat": _RepeatMatcher,
    "sequence": _SequenceMatcher,
}


# ── engine ──────────────────────────────────────────────────────────────────


class Engine:
    def __init__(self, ruleset: RuleSet, trusted: TrustedSets | None = None) -> None:
        """``trusted``: live sets the sensor maintains (allowlist ``allow_trusted``). Shared by
        reference, so updates apply without rebuilding the engine."""
        self.ruleset = ruleset
        self.trusted = trusted if trusted is not None else {}
        self._compiled = [
            (
                r,
                _AllowlistMatcher(r.match, self.trusted)
                if r.match.type == "allowlist"
                else _InSetMatcher(r.match, self.trusted)
                if r.match.type == "in_set"
                else _MATCHERS[r.match.type](r.match),
            )
            for r in ruleset.enabled
        ]
        self._reported: set[tuple[str, str, str, str]] = set()

    def process(self, event: AgentEvent) -> Verdict:
        doc = event.model_dump(mode="json")
        session = _session_key(doc)
        verdict = Verdict(event)
        for rule, matcher in self._compiled:
            if not condition_holds(doc, rule.when):
                continue
            if rule.unless and condition_holds(doc, rule.unless):
                continue
            raw = matcher.check(event, doc)
            if raw is None:
                continue
            dedup_key = (rule.id, *session, raw.key)
            first_time = dedup_key not in self._reported
            if rule.dedup == "session":
                self._reported.add(dedup_key)
            report = first_time or rule.dedup == "none"
            verdict.hits.append(Hit(rule, raw.key, raw.explanation, raw.evidence_event_ids, report))
            if report:
                verdict.findings.append(self._finding(rule, event, raw))
        if event.kind is EventKind.SESSION_END:
            self._forget_session(session)
        return verdict

    def replay(self, events: Iterable[AgentEvent]) -> list[Verdict]:
        return [self.process(e) for e in events]

    def _forget_session(self, session: tuple[str, str]) -> None:
        self._reported = {k for k in self._reported if (k[1], k[2]) != session}
        for _, matcher in self._compiled:
            if isinstance(matcher, _SequenceMatcher):
                matcher.forget_session(session)

    @staticmethod
    def _finding(rule: Rule, event: AgentEvent, raw: _RawHit) -> Finding:
        return Finding.from_event(
            event,
            rule_id=rule.id,
            rule_version=rule.version,
            severity=rule.severity,
            category=rule.category,
            title=rule.title,
            message=rule.message,
            recommended_action=rule.recommended_action,
            confidence=rule.confidence,
            tags=rule.tags,
            explanation=raw.explanation,
            evidence_event_ids=raw.evidence_event_ids,
            labels=_campaign_labels(rule, raw),
            response=Enforcement(
                action=rule.response,
                enforced=False,
                enforcer=event.source.sensor,
                # The adapter replaces this with what it actually did (Sensor.record).
                detail="not enforced: detection only",
            ),
        )


def _campaign_labels(rule: Rule, raw: _RawHit) -> dict[str, str]:
    indicator = indicator_of(raw.values) if CAMPAIGN_TAG in rule.tags else None
    return {INDICATOR: indicator} if indicator else {}

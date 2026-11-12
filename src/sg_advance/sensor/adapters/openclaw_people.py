"""Who is behind an OpenClaw session or run, on a multi-user (team) gateway.

The gateway knows each person as a *profile* (trusted-proxy / SSO identity → stable profile id).
The plugin's tool context does not carry it, so the sensor stitches it from the WebSocket side:

- ``users.list`` → ``{profiles: [{id, displayName, emails, effectiveRole, mergedInto}]}``: profile
  id → email. Read on connect and on every inventory refresh (``operator.read`` is enough).
- ``presence`` frames → ``presence[].user {id, email, name}``: same mapping for people who just
  signed in.
- user ``session.message`` → ``message.__openclaw {senderIdentity: {type: profile, id}, senderName,
  idempotencyKey: "<runId>:user"}``: who started that run. Most precise: a shared session can have
  writers other than its owner.
- session payloads (``sessions.list`` rows, ``sessions.changed``, ``session.message``) →
  ``owner.actor {type: human, identity: {type: profile, id}, label}``: who owns the session.

Attribution order for an event: the run's sender, then the session owner, then the sensor's
default user (``--user``; on a solo gateway that is the only person, so nothing changes there).

Profiles and session owners are kept in ``state_path`` (owner-only file): after a sensor restart
the plugin can be judging calls before the WebSocket side has reconnected and re-read them.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..state import write_private

log = logging.getLogger(__name__)

PROFILE_PREFIX = "openclaw-profile:"
_CAP = 10_000  # bounded memory on long-running gateways


@dataclass(frozen=True)
class Person:
    profile_id: str
    email: str | None = None
    name: str | None = None
    role: str | None = None

    @property
    def user_id(self) -> str:
        # Email is what the rest of the company (SSO, HR, the console) knows people by.
        return self.email or f"{PROFILE_PREFIX}{self.profile_id}"


@dataclass(frozen=True)
class Attribution:
    principal: dict[str, Any]
    labels: dict[str, str] = field(default_factory=dict)


def _bounded_set(d: OrderedDict[str, Any], key: str, value: Any) -> None:
    d[key] = value
    d.move_to_end(key)
    while len(d) > _CAP:
        d.popitem(last=False)


def _profile_of(actor: Any) -> tuple[str, str | None] | None:
    """(profile id, label) of a human actor ``{type: human, identity: {type: profile, id}, label}``."""
    if not isinstance(actor, dict) or actor.get("type") not in (None, "human"):
        return None
    ident = actor.get("identity")
    pid = ident.get("id") if isinstance(ident, dict) and ident.get("type") == "profile" else None
    if not isinstance(pid, str) or not pid:
        return None
    label = actor.get("label")
    return pid, label if isinstance(label, str) else None


class OpenClawPeople:
    """Shared by the WebSocket adapter (which learns) and the plugin API (which only asks)."""

    def __init__(self, state_path: Path | None = None) -> None:
        self.people: dict[str, Person] = {}
        self.merged: dict[str, str] = {}  # merged profile id -> surviving id
        self.run_sender: OrderedDict[str, str] = OrderedDict()  # runId -> profile id
        self.session_owner: OrderedDict[str, str] = OrderedDict()  # sessionKey -> profile id
        self.state_path = state_path
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            doc = json.loads(self.state_path.read_text("utf-8"))
            for p in doc.get("people") or []:
                self.people[p["profile_id"]] = Person(**p)
            self.merged.update(doc.get("merged") or {})
            for key, pid in (doc.get("session_owner") or {}).items():
                _bounded_set(self.session_owner, key, pid)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            log.warning("ignoring unreadable %s: %s", self.state_path, e)

    def save(self) -> None:
        if self.state_path is None:
            return
        doc = {
            "people": [asdict(p) for p in self.people.values()],
            "merged": self.merged,
            "session_owner": dict(self.session_owner),
        }
        try:
            write_private(self.state_path, json.dumps(doc, ensure_ascii=False))
        except OSError as e:
            log.warning("could not save %s: %s", self.state_path, e)

    # ── learning ─────────────────────────────────────────────────────────────

    def _canon(self, pid: str) -> str:
        seen = set()
        while pid in self.merged and pid not in seen:
            seen.add(pid)
            pid = self.merged[pid]
        return pid

    def _learn(self, pid: str, *, email: Any = None, name: Any = None, role: Any = None) -> None:
        old = self.people.get(pid) or Person(pid)
        self.people[pid] = Person(
            pid,
            email=email if isinstance(email, str) and email else old.email,
            name=name if isinstance(name, str) and name else old.name,
            role=role if isinstance(role, str) and role else old.role,
        )

    def learn_profiles(self, payload: Any) -> None:
        """``users.list`` payload."""
        profiles = payload.get("profiles") if isinstance(payload, dict) else None
        for p in profiles if isinstance(profiles, list) else []:
            pid = p.get("id") if isinstance(p, dict) else None
            if not isinstance(pid, str) or not pid:
                continue
            if isinstance(p.get("mergedInto"), str) and p["mergedInto"]:
                self.merged[pid] = p["mergedInto"]
            emails = [e for e in p.get("emails") or [] if isinstance(e, str) and e]
            self._learn(
                pid,
                email=emails[0] if emails else None,
                name=p.get("displayName"),
                role=p.get("effectiveRole"),
            )

    def learn_sessions(self, payload: Any) -> None:
        """``sessions.list`` payload (sessions that existed before the sensor connected)."""
        sessions = payload.get("sessions") if isinstance(payload, dict) else None
        for s in sessions if isinstance(sessions, list) else []:
            if isinstance(s, dict) and isinstance(s.get("key"), str):
                self._learn_session(s["key"], s)

    def _learn_session(self, key: str, s: dict[str, Any]) -> None:
        owner = s.get("owner")
        found = _profile_of(owner.get("actor") if isinstance(owner, dict) else None) or _profile_of(
            s.get("createdActor")
        )
        if found:
            pid, label = found
            self._learn(pid, name=label)
            _bounded_set(self.session_owner, key, pid)

    def observe(self, frame: dict[str, Any]) -> None:
        """Every gateway event frame passes through here before it is mapped."""
        name, p = frame.get("event"), frame.get("payload")
        if not isinstance(p, dict):
            return
        if name == "presence":
            for entry in p.get("presence") or []:
                user = entry.get("user") if isinstance(entry, dict) else None
                if isinstance(user, dict) and isinstance(user.get("id"), str):
                    self._learn(user["id"], email=user.get("email"), name=user.get("name"))
            return
        key = p.get("sessionKey")
        if name in ("sessions.changed", "session.message") and isinstance(key, str):
            self._learn_session(key, p)
        if name == "session.message":
            self._learn_sender(p)

    def _learn_sender(self, p: dict[str, Any]) -> None:
        msg = p.get("message")
        if not isinstance(msg, dict) or msg.get("role") != "user":
            return
        meta = msg.get("__openclaw")
        if not isinstance(meta, dict):
            return
        found = _profile_of(
            {"type": "human", "identity": meta.get("senderIdentity"), "label": meta.get("senderName")}
        )
        idem = meta.get("idempotencyKey")
        if not found or not isinstance(idem, str) or not idem.endswith(":user"):
            return
        pid, label = found
        self._learn(pid, name=label)
        _bounded_set(self.run_sender, idem.removesuffix(":user"), pid)

    # ── asking ───────────────────────────────────────────────────────────────

    def attribute(self, session_key: str | None, run_id: str | None, default_user: str) -> Attribution:
        sender = self.run_sender.get(run_id) if isinstance(run_id, str) else None
        owner = self.session_owner.get(session_key) if isinstance(session_key, str) else None
        pid, how = (sender, "sender") if sender else (owner, "session_owner")
        if not pid:
            return Attribution({"user_id": default_user})
        person = self.people.get(self._canon(pid)) or Person(self._canon(pid))
        principal: dict[str, Any] = {"user_id": person.user_id}
        if person.name:
            principal["display_name"] = person.name
        if person.role:
            principal["groups"] = (f"openclaw-role:{person.role}",)
        labels = {"openclaw.attribution": how, "openclaw.profile_id": person.profile_id}
        if sender and owner and self._canon(owner) != person.profile_id:
            # Someone wrote into a session another person owns (shared session): keep both.
            o = self.people.get(self._canon(owner)) or Person(self._canon(owner))
            labels["openclaw.session_owner"] = o.user_id
        return Attribution(principal, labels)

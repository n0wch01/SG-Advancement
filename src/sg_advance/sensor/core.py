"""Sensor core: enrollment, signed policy cache, local detection, spool.

Adapters turn agent-native activity into AgentEvents and call ``Sensor.process``. The verdict
comes back synchronously so blocking adapters (hooks, proxies) can enforce it; shipping to the
control plane happens later through the spool and never blocks the agent.

    adapter ──AgentEvent──▶ Sensor.process ──▶ Engine (local rules) ──▶ Verdict ──▶ adapter enforces
                                   └──▶ redact ──▶ Spool ──flush──▶ control plane
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from .. import __version__
from ..detect import Engine, Verdict
from ..pki import fingerprint, key_pem, make_csr, new_key
from ..policy import PolicyBundle, PolicyVerificationError, key_id, load_public_key
from ..redact import redact_event
from ..schema import AgentEvent, Enforcement, EventKind
from . import delegation as delegation_mod
from . import downloads as downloads_mod
from . import lineage as lineage_mod
from .client import ControlPlaneClient, ControlPlaneError, Offline, Transport, urllib_transport
from .priority import event_priority
from .spool import FlushResult, Spool
from .state import Credentials, SensorHome, now_utc, write_private

log = logging.getLogger(__name__)


class SensorError(Exception):
    pass


class NotEnrolled(SensorError):
    pass


class NoPolicy(SensorError):
    """Neither the server nor a valid local cache could provide a policy."""


class SyncStatus(StrEnum):
    UPDATED = "updated"  # new bundle fetched, verified and cached
    UNCHANGED = "unchanged"  # 304
    OFFLINE = "offline"  # kept the policy we had
    REFUSED = "refused"  # the server said no (revoked device, bad token or certificate); cache kept


def enroll(
    home: SensorHome,
    server_url: str,
    enrollment_token: str,
    *,
    device_id: str | None = None,
    pinned_key: str | None = None,
    transport: Transport | None = None,
    ca_file: Path | None = None,
    ca_sha256: str | None = None,
) -> Credentials:
    """Register this endpoint. ``pinned_key`` (option B) must match the server's policy key;
    without it the key from the enroll response is trusted on first use (option A).

    M12: an ``https`` server is the LAN gateway. Then ``ca_file`` is the device CA to trust (its
    SHA-256 must equal ``ca_sha256`` when given: the install command pins it), and the sensor makes
    a key here and enrolls with a CSR; the signed client certificate comes back with the token."""
    if home.load_credentials() is not None:
        raise SensorError(f"already enrolled ({home.credentials_path}); remove it to re-enroll")
    lan = server_url.lower().startswith("https://")
    ca_pem = key = None
    if lan:
        if ca_file is None:
            raise SensorError("an https control plane needs --ca-file (device CA, see install command)")
        ca_pem = ca_file.read_text("utf-8")
        got = fingerprint(ca_pem)
        if ca_sha256 is not None and got != ca_sha256.lower().replace(":", ""):
            raise SensorError(f"CA fingerprint {got} does not match the pinned {ca_sha256}")
        key = new_key()
        if transport is None:
            ctx = ssl.create_default_context(cadata=ca_pem)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            transport = urllib_transport(context=ctx)
    client = ControlPlaneClient(server_url, transport=transport)
    if pinned_key is not None:
        expected = key_id(load_public_key(pinned_key))
        # Check before spending the (single-use) enrollment token.
        got = client.health().get("policy_key_id")
        if got != expected:
            raise SensorError(f"server policy key {got} does not match the pinned key {expected}")
    resp = client.enroll(
        enrollment_token,
        device_id=device_id,
        hostname=socket.gethostname(),
        os=f"{platform.system().lower()} {platform.release()}",
        sensor_version=__version__,
        csr=make_csr(key, device_id) if key is not None else None,
    )
    if lan:
        cert = resp.get("client_certificate")
        ca_back = resp.get("ca_certificate")
        if not cert or not ca_back or fingerprint(ca_back) != fingerprint(ca_pem):  # type: ignore[arg-type]
            raise SensorError("the control plane did not return a certificate from the pinned CA; not saving")
        home.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(home.key_path, key_pem(key))  # type: ignore[arg-type]
        write_private(home.cert_path, cert)
        write_private(home.ca_path, ca_pem)  # type: ignore[arg-type]
    server_key = resp["policy_public_key"]
    if pinned_key is not None and server_key != pinned_key:
        raise SensorError("enroll response carried a different policy key than the pinned one; not saving")
    creds = Credentials(
        server_url=server_url,
        device_id=resp["device_id"],
        device_token=resp["device_token"],
        policy_public_key=pinned_key or server_key,
        policy_key_id=key_id(pinned_key or server_key),
        key_pinned=pinned_key is not None,
        enrolled_at=now_utc(),
        client_certificate=lan,
    )
    home.save_credentials(creds)
    return creds


@dataclass
class ProcessResult:
    verdict: Verdict
    event: AgentEvent  # the stamped event the rules saw


_CHAT_KINDS = ("prompt.user", "message.assistant")


def withhold_chat_text(event: AgentEvent) -> AgentEvent:
    """Drop the text of a prompt/reply, keeping that it happened and how long it was."""
    p = event.payload
    if p.kind.value not in _CHAT_KINDS or p.withheld:  # type: ignore[union-attr]
        return event
    text = p.text  # type: ignore[union-attr]
    payload = p.model_copy(update={"text": "", "withheld": True, "text_chars": len(text)})
    return event.model_copy(update={"payload": payload, "raw": None})


RECORD_PREVIEW = 4000  # tool results are judged whole (up to the enforcement point's limit), kept short


def _short_result(event: AgentEvent) -> AgentEvent:
    p = event.payload
    if (
        event.kind is not EventKind.TOOL_RESULT
        or len(getattr(p, "output_preview", None) or "") <= RECORD_PREVIEW
    ):
        return event
    short = p.output_preview[:RECORD_PREVIEW]  # type: ignore[union-attr]
    return event.model_copy(update={"payload": p.model_copy(update={"output_preview": short})})


class Sensor:
    def __init__(self, home: SensorHome, transport: Transport | None = None) -> None:
        creds = home.load_credentials()
        if creds is None:
            raise NotEnrolled(f"not enrolled: run `sga-sensor enroll` (looked in {home.root})")
        self.home = home
        self.creds = creds
        self._key = load_public_key(creds.policy_public_key)
        if transport is None:
            transport = urllib_transport(context=home.ssl_context())
        self.client = ControlPlaneClient(creds.server_url, creds.device_token, transport)
        self.spool = Spool(home.spool_path)
        self.policy: PolicyBundle | None = None
        self.engine: Engine | None = None
        # Values adapters have verified (e.g. openclaw_plugins: plugin ids whose code matches a
        # signed, approved package). Rules opt in with ``allow_trusted``. Persisted so a restart
        # doesn't flag known-good plugins before the first integrity scan finishes.
        self.trusted: dict[str, set[str]] = self._load_trusted()
        # Prompts and replies are employees' conversations: only those a rule hit leave the endpoint
        # with their text (detection already saw the full text locally). ``--keep-chat-text`` opts out.
        self.keep_chat_text = False
        # Zero trust (KISA agentic AI ZT guide 2.4.3): a cached policy has a lifetime. When the
        # control plane has not confirmed the policy is current for this long, tool calls carry
        # labels.sga_policy_stale and the signed rules decide (rules/zero_trust.yaml).
        self.policy_max_age = timedelta(hours=float(os.environ.get("SGA_POLICY_MAX_AGE_HOURS", "72")))
        self._checked_at = self._load_checked_at()
        # Device posture for zero-trust access decisions: each check (Claude Code hook settings,
        # agent discovery) reports why this PC falls short; no report yet means unknown.
        self.posture: dict[str, list[str]] = {}
        self._posture_at: dict[str, datetime] = {}
        # Only a sensor that checks its PC labels posture (fail closed: a PC that should be checked but
        # has no fresh result is "unknown"). The file keeps the last results for the hook's degraded path.
        self.posture_expected = False
        self._load_posture()
        # Phase 2 (CLAUDE.md): which tool calls carry protected test DB data, and where to (lineage.py).
        self.lineage = lineage_mod.LineageStore(home.root / "lineage.json")
        self._call_sources: dict[str, tuple[str, datetime]] = {}
        # Follow-up scenario 2: files shell commands downloaded, labelled when a later command runs them.
        self.downloads = downloads_mod.DownloadTracker()
        # Follow-up scenario 3: a subagent given more permission than its parent (delegation control).
        self.delegation = delegation_mod.DelegationChecker()
        # Outcome model (2026-11-13): tool calls refused by handing the decision to the agent, kept until
        # their result shows up (then the refusal was not applied) or they age out.
        self._refused: dict[str, tuple[list[str], datetime]] = {}

    POSTURE_MAX_AGE = timedelta(hours=1)

    @property
    def _posture_path(self) -> Path:
        return self.home.root / "posture.json"

    def _load_posture(self) -> None:
        try:
            doc = json.loads(self._posture_path.read_text("utf-8"))
            for check, row in doc.get("checks", {}).items():
                self.posture[check] = list(row["reasons"])
                self._posture_at[check] = datetime.fromisoformat(row["at"])
            self.posture_expected = True
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def set_posture(self, check: str, reasons: list[str]) -> None:
        if self.posture.get(check) != reasons:
            log.info("posture %s: %s", check, "; ".join(reasons) or "ok")
        self.posture[check] = list(reasons)
        self._posture_at[check] = now_utc()
        self.posture_expected = True
        doc = {
            "checks": {
                c: {"reasons": r, "at": self._posture_at[c].isoformat()} for c, r in self.posture.items()
            }
        }
        try:
            write_private(self._posture_path, json.dumps(doc))
        except OSError as e:
            log.warning("could not keep posture results: %s", e)

    def posture_state(self, now: datetime | None = None) -> tuple[str, list[str]] | None:
        """(ok | degraded | unknown, reasons), or None when this sensor does not check its PC."""
        if not self.posture_expected:
            return None
        now = now or now_utc()
        fresh = {
            c: r
            for c, r in self.posture.items()
            if now - self._posture_at.get(c, now) <= self.POSTURE_MAX_AGE
        }
        if not fresh:
            return "unknown", []
        reasons = list(dict.fromkeys(r for rs in fresh.values() for r in rs))
        return ("degraded" if reasons else "ok"), reasons

    # ── policy freshness ─────────────────────────────────────────────────────

    @property
    def _checked_path(self) -> Path:
        return self.home.root / "policy-checked.json"

    def _load_checked_at(self) -> datetime | None:
        try:
            return datetime.fromisoformat(json.loads(self._checked_path.read_text("utf-8"))["at"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
        try:  # sensors from before this file: the cache's own write time
            return datetime.fromtimestamp(self.home.policy_path.stat().st_mtime, tz=now_utc().tzinfo)
        except OSError:
            return None

    def _mark_checked(self) -> None:
        self._checked_at = now_utc()
        write_private(self._checked_path, json.dumps({"at": self._checked_at.isoformat()}))

    def policy_age(self, now: datetime | None = None) -> timedelta | None:
        """Time since the control plane last confirmed this policy is current (None: never)."""
        return None if self._checked_at is None else (now or now_utc()) - self._checked_at

    def policy_stale(self, now: datetime | None = None) -> bool:
        age = self.policy_age(now)
        return age is None or age > self.policy_max_age

    # ── trusted sets ─────────────────────────────────────────────────────────

    @property
    def _trusted_path(self) -> Path:
        return self.home.root / "trusted.json"

    def _load_trusted(self) -> dict[str, set[str]]:
        try:
            doc = json.loads(self._trusted_path.read_text("utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: set(v) for k, v in doc.items() if isinstance(v, list)}

    def set_trusted(self, name: str, values: set[str]) -> None:
        """Replace one trusted set in place (engines hold a reference) and persist it."""
        if self.trusted.get(name) == values:
            return
        self.trusted[name] = set(values)
        write_private(self._trusted_path, json.dumps({k: sorted(v) for k, v in self.trusted.items()}))

    # ── policy ───────────────────────────────────────────────────────────────

    def _install(self, bundle: PolicyBundle) -> None:
        self.engine = Engine(bundle.to_ruleset(self._key), self.trusted)  # verifies hash + signature
        self.policy = bundle

    def load_cached_policy(self) -> bool:
        p = self.home.policy_path
        if not p.exists():
            return False
        try:
            self._install(PolicyBundle.model_validate_json(p.read_text("utf-8")))
        except (ValueError, PolicyVerificationError) as e:
            # A cache that fails verification was tampered with or corrupted: never use it.
            log.warning("ignoring cached policy %s: %s", p, e)
            return False
        return True

    def sync_policy(self) -> SyncStatus:
        try:
            bundle = self.client.get_policy(self.policy.version if self.policy else None)
        except Offline as e:
            log.info("policy sync offline: %s", e)
            return SyncStatus.OFFLINE
        if bundle is None:
            self._mark_checked()
            return SyncStatus.UNCHANGED
        self._install(bundle)  # raises PolicyVerificationError before touching the cache
        write_private(self.home.policy_path, bundle.model_dump_json())
        self._mark_checked()
        return SyncStatus.UPDATED

    def start(self) -> SyncStatus:
        """Load the cached policy, then try the server. Keeps working offline on the cache."""
        self.load_cached_policy()
        try:
            status = self.sync_policy()
        except ControlPlaneError as e:
            if self.engine is None:
                raise NoPolicy(f"server refused policy ({e}) and there is no valid cache") from e
            # Keep enforcing the last signed policy: being cut off must not switch protection off.
            log.warning("policy sync refused, using cache: %s", e)
            return SyncStatus.REFUSED
        if self.engine is None:
            raise NoPolicy("control plane unreachable and there is no valid cached policy")
        return status

    # ── events ───────────────────────────────────────────────────────────────

    def stamp(self, event: AgentEvent) -> AgentEvent:
        """Adapters don't need to know the enrolled identity; the core fills it in. Tool calls also
        carry the endpoint's state the zero-trust rules decide on (labels.sga_*)."""
        ep = event.endpoint
        update: dict[str, object] = {}
        if ep.device_id != self.creds.device_id:
            update["endpoint"] = ep.model_copy(update={"device_id": self.creds.device_id})
        if any(k in event.labels for k in self._OWN_LABELS):  # the sensor's own; never taken from input
            update["labels"] = {k: v for k, v in event.labels.items() if k not in self._OWN_LABELS}
        if event.kind is EventKind.TOOL_CALL:
            base = update.get("labels", event.labels)
            clean = event.model_copy(update={"labels": base}) if "labels" in update else event
            labels = (
                self.state_labels()
                | self.lineage.labels_for(clean)
                | self.downloads.labels_for(clean)
                | self.delegation.labels_for(clean)
            )
            if labels:
                update["labels"] = base | labels  # type: ignore[operator]
            self._remember_source(clean)
        elif event.kind is EventKind.TOOL_RESULT:
            if tracked := self.lineage.labels_for(event):
                update["labels"] = update.get("labels", event.labels) | tracked  # type: ignore[operator]
            if source := self._source_of(event):
                update["labels"] = update.get("labels", event.labels) | {"sga_input_source": source}  # type: ignore[operator]
            refused = self._refused.pop(getattr(event.payload, "call_id", ""), None)
            if refused is not None:
                update["labels"] = (
                    update.get("labels", event.labels)
                    | {  # type: ignore[operator]
                        "sga_enforcement_contradicted": "true",
                        "sga_contradicted_findings": ",".join(refused[0])[:500],
                    }
                )
        return event.model_copy(update=update) if update else event

    # Follow-up scenario 1 (docs/external-input.md): where a tool result came from = where its call talked
    # to, read from the call's own arguments (URL host, MCP server, search, local). The rules decide
    # what is external. Calls are remembered until their result arrives (bounded).
    _OWN_LABELS = (*lineage_mod.LABELS, "sga_input_source", downloads_mod.LABEL, *delegation_mod.LABELS)
    SOURCE_KEEP = timedelta(hours=1)
    SOURCE_MAX = 5000

    def _remember_source(self, call: AgentEvent) -> None:
        call_id = getattr(call.payload, "call_id", None)
        if not call_id:
            return
        if len(self._call_sources) >= self.SOURCE_MAX:
            cutoff = now_utc() - self.SOURCE_KEEP
            self._call_sources = {k: v for k, v in self._call_sources.items() if v[1] >= cutoff}
            while len(self._call_sources) >= self.SOURCE_MAX:
                self._call_sources.pop(next(iter(self._call_sources)))
        self._call_sources[call_id] = (",".join(lineage_mod.destinations(call))[:500], now_utc())

    def _source_of(self, result: AgentEvent) -> str | None:
        known = self._call_sources.pop(getattr(result.payload, "call_id", ""), None)
        if known is not None:
            return known[0]
        server = lineage_mod.mcp_server_of(result)  # the gateway knows the server from the result itself
        return f"mcp:{server}" if server else None

    REFUSED_KEEP = timedelta(hours=24)
    REFUSED_MAX = 5000

    def _remember_refused(self, call_id: str, finding_ids: list[str]) -> None:
        now = now_utc()
        if len(self._refused) >= self.REFUSED_MAX:
            self._refused = {k: v for k, v in self._refused.items() if now - v[1] < self.REFUSED_KEEP}
        self._refused[call_id] = (finding_ids, now)

    def state_labels(self) -> dict[str, str]:
        """Endpoint state for the zero-trust rules (rules/zero_trust.yaml)."""
        labels: dict[str, str] = {}
        posture = self.posture_state()
        if posture is not None:
            labels["sga_posture"] = posture[0]
            if posture[1]:
                labels["sga_posture_reasons"] = "; ".join(posture[1])[:500]
        if self.policy_stale():
            age = self.policy_age()
            labels["sga_policy_stale"] = "true"
            labels["sga_policy_age_hours"] = (
                "unknown" if age is None else str(int(age.total_seconds() // 3600))
            )
        return labels

    def evaluate(self, event: AgentEvent) -> ProcessResult:
        """Step 1: stamp + detect. Nothing is queued yet, so the adapter can enforce first
        (possibly asynchronously) and report what happened through ``record``."""
        if self.engine is None:
            raise NoPolicy("call start() first")
        event = self.stamp(event)
        verdict = self.engine.process(event)  # detection sees the original (unredacted) event
        return ProcessResult(verdict, event)

    _STATE_LABELS = ("sga_policy_stale", "sga_policy_age_hours", "sga_posture", "sga_posture_reasons")
    _BLOCKING = frozenset({"block", "abort_session", "quarantine"})

    def recheck(self, event: AgentEvent) -> list[Any]:
        """The hits that would block this call *now* (latest policy, sets, posture, freshness), without
        recording anything or touching the live engine's state. Used right before an approved call is
        released (CLAUDE.md phase 1). Sequence rules start empty here: they were judged when it was held."""
        if self.engine is None:
            raise NoPolicy("call start() first")
        fresh = Engine(self.engine.ruleset, self.trusted)
        clean = event.model_copy(
            update={"labels": {k: v for k, v in event.labels.items() if k not in self._STATE_LABELS}}
        )
        verdict = fresh.process(self.stamp(clean))
        return [h for h in verdict.hits if str(h.rule.response.value) in self._BLOCKING]

    def record(self, result: ProcessResult, enforcement: Enforcement | None = None) -> None:
        """Step 2: queue the redacted event and its findings, with the enforcement outcome."""
        findings = result.verdict.findings
        if enforcement is not None:
            findings = [*findings, *self._enforced_repeats(result.verdict, enforcement)]
            findings = [f.model_copy(update={"response": enforcement}) for f in findings]
            result.verdict.findings = findings
            if (
                result.event.kind is EventKind.TOOL_CALL
                and enforcement.stage == "blocked"
                and enforcement.confirmation == "unconfirmed"
            ):
                self._remember_refused(result.event.payload.call_id, [f.finding_id for f in findings])  # type: ignore[union-attr]
        findings = self._lineage(result, findings)
        result.verdict.findings = findings
        event = redact_event(_short_result(self._mask_protected(result.event)))
        if not self.keep_chat_text and not result.verdict.hits:
            event = withhold_chat_text(event)
        self.spool.add([event, *findings], event_priority(result.event, result.verdict))

    def _lineage(self, result: ProcessResult, findings: list[Any]) -> list[Any]:
        """Register protected values a ``lineage:source`` rule found (hashes only), and point a
        ``lineage:sink`` finding at the reads its data came from, so the console shows one flow."""
        for hit in result.verdict.hits:
            if lineage_mod.SOURCE_TAG in hit.rule.tags and hit.collected:
                self.lineage.register(result.event, list(hit.collected))
        sources = self.lineage.source_ids(result.event.labels)
        if not sources:
            return findings
        return [
            f.model_copy(
                update={
                    "evidence_event_ids": (*sources, *(i for i in f.evidence_event_ids if i not in sources))
                }
            )
            if lineage_mod.SINK_TAG in f.tags
            else f
            for f in findings
        ]

    def _mask_protected(self, event: AgentEvent) -> AgentEvent:
        """Protected test DB values never leave the endpoint: the read and the call carrying them are
        recorded with the values replaced (the hashes stay on this PC)."""
        p = event.payload
        if event.kind is EventKind.TOOL_RESULT and getattr(p, "output_preview", None):
            masked = self.lineage.mask(p.output_preview)  # type: ignore[union-attr]
            if masked != p.output_preview:  # type: ignore[union-attr]
                return event.model_copy(update={"payload": p.model_copy(update={"output_preview": masked})})
        elif event.kind is EventKind.TOOL_CALL and event.labels.get("sga_data_class"):
            args = json.loads(self.lineage.mask(json.dumps(p.arguments, ensure_ascii=False)))  # type: ignore[union-attr]
            return event.model_copy(update={"payload": p.model_copy(update={"arguments": args})})
        return event

    # Stages where the enforcement point acted on the call itself (not detection or the agent's own prompt).
    _ENFORCED_STAGES = frozenset({"held", "blocked", "result_withheld", "session_aborted", "quarantined"})

    def _enforced_repeats(self, verdict: Any, enforcement: Enforcement) -> list[Any]:
        """Hits dedup suppressed, reported anyway when this call was really blocked or held (decision
        2026-11-13): each enforced call is its own record, labelled ``sga_repeat``."""
        if not enforcement.enforced or enforcement.stage not in self._ENFORCED_STAGES:
            return []
        repeat = {"sga_repeat": "true"}
        return [f.model_copy(update={"labels": f.labels | repeat}) for f in verdict.enforcing_repeats]

    def process(self, event: AgentEvent) -> ProcessResult:
        """evaluate + record, for observation-only callers (replay)."""
        result = self.evaluate(event)
        self.record(result)
        return result

    def flush(self) -> FlushResult:
        return self.spool.flush(self.client)

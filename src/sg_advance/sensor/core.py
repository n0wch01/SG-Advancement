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
import platform
import socket
import ssl
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .. import __version__
from ..detect import Engine, Verdict
from ..pki import fingerprint, key_pem, make_csr, new_key
from ..policy import PolicyBundle, PolicyVerificationError, key_id, load_public_key
from ..redact import redact_event
from ..schema import AgentEvent, Enforcement
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
            return SyncStatus.UNCHANGED
        self._install(bundle)  # raises PolicyVerificationError before touching the cache
        write_private(self.home.policy_path, bundle.model_dump_json())
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
        """Adapters don't need to know the enrolled identity; the core fills it in."""
        ep = event.endpoint
        if ep.device_id == self.creds.device_id:
            return event
        return event.model_copy(
            update={"endpoint": ep.model_copy(update={"device_id": self.creds.device_id})}
        )

    def evaluate(self, event: AgentEvent) -> ProcessResult:
        """Step 1: stamp + detect. Nothing is queued yet, so the adapter can enforce first
        (possibly asynchronously) and report what happened through ``record``."""
        if self.engine is None:
            raise NoPolicy("call start() first")
        event = self.stamp(event)
        verdict = self.engine.process(event)  # detection sees the original (unredacted) event
        return ProcessResult(verdict, event)

    def record(self, result: ProcessResult, enforcement: Enforcement | None = None) -> None:
        """Step 2: queue the redacted event and its findings, with the enforcement outcome."""
        findings = result.verdict.findings
        if enforcement is not None:
            findings = [f.model_copy(update={"response": enforcement}) for f in findings]
            result.verdict.findings = findings
        event = redact_event(result.event)
        if not self.keep_chat_text and not result.verdict.hits:
            event = withhold_chat_text(event)
        self.spool.add([event, *findings], event_priority(result.event, result.verdict))

    def process(self, event: AgentEvent) -> ProcessResult:
        """evaluate + record, for observation-only callers (replay)."""
        result = self.evaluate(event)
        self.record(result)
        return result

    def flush(self) -> FlushResult:
        return self.spool.flush(self.client)

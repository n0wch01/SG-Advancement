"""Sensor core: enrollment, signed policy cache, local detection, spool.

Adapters turn agent-native activity into AgentEvents and call ``Sensor.process``. The verdict
comes back synchronously so blocking adapters (hooks, proxies) can enforce it; shipping to the
control plane happens later through the spool and never blocks the agent.

    adapter ──AgentEvent──▶ Sensor.process ──▶ Engine (local rules) ──▶ Verdict ──▶ adapter enforces
                                   └──▶ redact ──▶ Spool ──flush──▶ control plane
"""

from __future__ import annotations

import logging
import platform
import socket
from dataclasses import dataclass
from enum import StrEnum

from .. import __version__
from ..detect import Engine, Verdict
from ..policy import PolicyBundle, PolicyVerificationError, key_id, load_public_key
from ..redact import redact_event
from ..schema import AgentEvent
from .client import ControlPlaneClient, ControlPlaneError, Offline, Transport
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


def enroll(
    home: SensorHome,
    server_url: str,
    enrollment_token: str,
    *,
    device_id: str | None = None,
    pinned_key: str | None = None,
    transport: Transport | None = None,
) -> Credentials:
    """Register this endpoint. ``pinned_key`` (option B) must match the server's policy key;
    without it the key from the enroll response is trusted on first use (option A)."""
    if home.load_credentials() is not None:
        raise SensorError(f"already enrolled ({home.credentials_path}); remove it to re-enroll")
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
    )
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
    )
    home.save_credentials(creds)
    return creds


@dataclass
class ProcessResult:
    verdict: Verdict
    event: AgentEvent  # the stamped event the rules saw


class Sensor:
    def __init__(self, home: SensorHome, transport: Transport | None = None) -> None:
        creds = home.load_credentials()
        if creds is None:
            raise NotEnrolled(f"not enrolled: run `sentinel-sensor enroll` (looked in {home.root})")
        self.home = home
        self.creds = creds
        self._key = load_public_key(creds.policy_public_key)
        self.client = ControlPlaneClient(creds.server_url, creds.device_token, transport)
        self.spool = Spool(home.spool_path)
        self.policy: PolicyBundle | None = None
        self.engine: Engine | None = None

    # ── policy ───────────────────────────────────────────────────────────────

    def _install(self, bundle: PolicyBundle) -> None:
        self.engine = Engine(bundle.to_ruleset(self._key))  # verifies hash + signature
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
            log.warning("policy sync failed, using cache: %s", e)
            return SyncStatus.OFFLINE
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

    def process(self, event: AgentEvent) -> ProcessResult:
        if self.engine is None:
            raise NoPolicy("call start() first")
        event = self.stamp(event)
        verdict = self.engine.process(event)  # detection sees the original (unredacted) event
        self.spool.add([redact_event(event), *verdict.findings], event_priority(event, verdict))
        return ProcessResult(verdict, event)

    def flush(self) -> FlushResult:
        return self.spool.flush(self.client)

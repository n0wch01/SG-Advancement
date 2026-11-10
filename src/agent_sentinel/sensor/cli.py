"""sentinel-sensor: enroll this endpoint, sync policy, replay events, ship the spool.

    sentinel-sensor enroll --server http://127.0.0.1:8000 --token set_...      # key from server (A)
    sentinel-sensor enroll --server ... --token ... --pin-key <base64>         # pinned key (B)
    sentinel-sensor status
    sentinel-sensor sync                       # pull policy + flush spool
    sentinel-sensor replay examples/events/claude_code.jsonl

The enrollment token can also come from SENTINEL_ENROLL_TOKEN (keeps it out of shell history
and the process list). SENTINEL_HOME overrides the state directory (default ~/.agent-sentinel).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

from ..detect.cli import print_verdict
from .adapters import ReplayAdapter
from .client import ControlPlaneError, Offline
from .core import NoPolicy, NotEnrolled, Sensor, SensorError, enroll
from .spool import FlushResult
from .state import SensorHome


def _print_flush(r: FlushResult) -> None:
    line = f"flush: sent {r.sent}, duplicates {r.duplicates}, dead {r.dead}, remaining {r.remaining}"
    print(line + (f"  ({r.error})" if r.error else ""))


def _cmd_enroll(home: SensorHome, args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("SENTINEL_ENROLL_TOKEN")
    if not token:
        print("enrollment token required: --token or SENTINEL_ENROLL_TOKEN", file=sys.stderr)
        return 2
    creds = enroll(home, args.server, token, device_id=args.device_id, pinned_key=args.pin_key)
    mode = "pinned at install" if creds.key_pinned else "trusted from enroll response"
    print(f"enrolled as {creds.device_id} → {creds.server_url}")
    print(f"policy key {creds.policy_key_id} ({mode})")
    print(f"state: {home.root}")
    return 0


def _cmd_status(home: SensorHome, _: argparse.Namespace) -> int:
    sensor = Sensor(home)
    c = sensor.creds
    cached = sensor.load_cached_policy()
    print(f"device     {c.device_id} @ {c.server_url}")
    print(f"policy key {c.policy_key_id} ({'pinned' if c.key_pinned else 'trust on first use'})")
    if cached and sensor.policy:
        print(f"policy     {sensor.policy.version[:16]}… ({len(sensor.policy.rules)} rules, cached)")
    else:
        print("policy     none cached")
    s = sensor.spool.stats()
    print(
        f"spool      {s['pending_events']} events, {s['pending_findings']} findings pending; "
        f"{s['dead']} dead; {s['dropped_events']} dropped"
    )
    for kind, item_id, err in sensor.spool.dead_letters()[:5]:
        print(f"  dead {kind} {item_id}: {err}")
    return 0


def _cmd_sync(home: SensorHome, _: argparse.Namespace) -> int:
    sensor = Sensor(home)
    status = sensor.start()
    print(f"policy: {status.value} ({sensor.policy.version[:16] if sensor.policy else '-'}…)")
    r = sensor.flush()
    _print_flush(r)
    return 0 if r.ok else 1


def _cmd_replay(home: SensorHome, args: argparse.Namespace) -> int:
    sensor = Sensor(home)
    status = sensor.start()
    print(f"policy: {status.value}")
    adapter = ReplayAdapter(args.events)
    actions: Counter[str] = Counter()
    for ev in adapter.events():
        res = sensor.process(ev)
        adapter.enforce(res.verdict)
        actions[res.verdict.action.value] += 1
        print_verdict(res.verdict, args.all)
    print(f"\nverdicts: {dict(actions)}")
    if args.no_flush:
        print("not flushed (--no-flush); run `sentinel-sensor sync` later")
        return 0
    r = sensor.flush()
    _print_flush(r)
    return 0 if r.ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel-sensor", description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", type=Path, help="state dir (default: $SENTINEL_HOME or ~/.agent-sentinel)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("enroll", help="register this endpoint with the control plane")
    p.add_argument("--server", required=True)
    p.add_argument("--token", help="enrollment token (or SENTINEL_ENROLL_TOKEN)")
    p.add_argument("--device-id")
    p.add_argument("--pin-key", help="base64 policy public key to require (option B)")
    p.set_defaults(fn=_cmd_enroll)

    sub.add_parser("status", help="show identity, cached policy, spool").set_defaults(fn=_cmd_status)
    sub.add_parser("sync", help="pull policy and flush the spool").set_defaults(fn=_cmd_sync)

    p = sub.add_parser("replay", help="feed AgentEvent JSONL through the sensor")
    p.add_argument("events", nargs="+", type=Path)
    p.add_argument("--all", action="store_true", help="also print events without hits")
    p.add_argument("--no-flush", action="store_true", help="only queue; don't ship")
    p.set_defaults(fn=_cmd_replay)

    args = ap.parse_args(argv)
    home = SensorHome(args.home)
    try:
        return args.fn(home, args)
    except (NotEnrolled, NoPolicy, SensorError, ControlPlaneError, Offline) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""sga-sensor: enroll this endpoint, sync policy, replay events, ship the spool.

    sga-sensor enroll --server http://127.0.0.1:8000 --token set_...      # key from server (A)
    sga-sensor enroll --server ... --token ... --pin-key <base64>         # pinned key (B)
    sga-sensor status
    sga-sensor sync                       # pull policy + flush spool
    sga-sensor replay examples/events/claude_code.jsonl
    sga-sensor run --openclaw                  # daemon: watch the local OpenClaw gateway + its config
    sga-sensor run --no-local-api              # daemon: only report agent installs on this PC

The OpenClaw gateway token comes from OPENCLAW_GATEWAY_TOKEN (never from argv).
The enrollment token can also come from SGA_ENROLL_TOKEN (keeps it out of shell history
and the process list). SGA_HOME overrides the state directory (default ~/.sg-advance).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import logging
import os
import socket
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
    token = args.token or os.environ.get("SGA_ENROLL_TOKEN")
    if not token:
        print("enrollment token required: --token or SGA_ENROLL_TOKEN", file=sys.stderr)
        return 2
    creds = enroll(
        home,
        args.server,
        token,
        device_id=args.device_id,
        pinned_key=args.pin_key,
        ca_file=args.ca_file,
        ca_sha256=args.ca_sha256,
    )
    mode = "pinned at install" if creds.key_pinned else "trusted from enroll response"
    print(f"enrolled as {creds.device_id} → {creds.server_url}")
    print(f"policy key {creds.policy_key_id} ({mode})")
    if creds.client_certificate:
        print(f"client certificate {home.cert_path} (key stays in {home.key_path})")
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
    if s["dropped_events"]:
        levels = ", ".join(
            f"{k.removeprefix('dropped_')} {v}"
            for k, v in s.items()
            if k.startswith("dropped_") and k != "dropped_events"
        )
        print(f"           dropped by priority: {levels}")
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
        actions[res.verdict.action.value] += 1
        print_verdict(res.verdict, args.all)
    print(f"\nverdicts: {dict(actions)}")
    if args.no_flush:
        print("not flushed (--no-flush); run `sga-sensor sync` later")
        return 0
    r = sensor.flush()
    _print_flush(r)
    return 0 if r.ok else 1


def _openclaw_token(home: SensorHome, token_file: Path | None) -> str:
    """Gateway token: OPENCLAW_GATEWAY_TOKEN, else a 0600 file (default <home>/openclaw-token).
    A file keeps the secret out of launchd plists and shell history."""
    return _gateway_secret(home, token_file, "OPENCLAW_GATEWAY_TOKEN", "openclaw-token")


def _openclaw_password(home: SensorHome, password_file: Path | None) -> str:
    """Gateway password (team gateways in trusted-proxy mode): OPENCLAW_GATEWAY_PASSWORD, else a
    0600 file (default <home>/openclaw-password)."""
    return _gateway_secret(home, password_file, "OPENCLAW_GATEWAY_PASSWORD", "openclaw-password")


def _gateway_secret(home: SensorHome, file: Path | None, env: str, default_name: str) -> str:
    if os.environ.get(env):
        return os.environ[env]
    path = file or home.root / default_name
    if path.exists():
        # Windows has no mode bits (files in the user's profile are private by ACL): POSIX only.
        if sys.platform != "win32" and path.stat().st_mode & 0o077:
            raise SensorError(f"{path} must not be readable by others (chmod 600)")
        return path.read_text("utf-8").strip()
    return ""


def _cmd_run(home: SensorHome, args: argparse.Namespace) -> int:
    from .adapters.base import AdapterContext
    from .daemon import Daemon

    if args.log_file:  # a windowless service (Windows pythonw) has no console to write to
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        filename=str(args.log_file) if args.log_file else None,
        encoding="utf-8" if args.log_file else None,
    )
    sensor = Sensor(home)
    sensor.keep_chat_text = args.keep_chat_text
    adapters: list = []
    if args.openclaw:
        try:
            import websockets  # noqa: F401  # optional dependency
        except ImportError:
            print("--openclaw needs the websockets package: install sg-advance[openclaw]", file=sys.stderr)
            return 2
        from .adapters.openclaw import OpenClawAdapter

        adapters.append(
            OpenClawAdapter(
                args.openclaw,
                token=_openclaw_token(home, args.openclaw_token_file),
                password=_openclaw_password(home, args.openclaw_password_file),
                enforce=not args.observe_only,
                gate_exec=args.gate_exec,
                capture=args.capture,
            )
        )
        if not args.no_openclaw_config:  # baseline watch (M5d): same gateway, its config file
            from .adapters.openclaw_config import OpenClawConfigAdapter

            adapters.append(OpenClawConfigAdapter(args.openclaw_config))
        if not args.no_openclaw_integrity:  # installed code vs. signed packages (M5d)
            from .adapters.openclaw_integrity import OpenClawIntegrityAdapter

            adapters.append(
                OpenClawIntegrityAdapter(interval=args.integrity_interval, quarantine=not args.observe_only)
            )
    if not args.no_claude_code:  # Claude Code's guard hook in place? (M6; silent if not installed)
        from .adapters.claude_code_config import ClaudeCodeConfigAdapter

        adapters.append(ClaudeCodeConfigAdapter())
    if not args.no_discovery:  # agent installs on this endpoint, managed or shadow (M5d)
        from .adapters.agent_discovery import AgentDiscoveryAdapter

        watched = [args.openclaw_config] if args.openclaw and not args.no_openclaw_config else []
        gateway_url = args.mcp_gateway_url or (
            f"http://{args.mcp_gateway}/mcp/" if args.mcp_gateway else None
        )
        adapters.append(
            AgentDiscoveryAdapter(
                watched_configs=watched, interval=args.discovery_interval, gateway_url=gateway_url
            )
        )
    if args.egress_proxy:  # the agent network's only way out, judged by the policy (M5d)
        from .adapters.egress_proxy import EgressProxyAdapter

        adapters.append(
            EgressProxyAdapter(
                args.egress_proxy,
                enforce=args.egress_enforce,
                internal_suffixes=tuple(args.egress_internal_suffix)
                or (".corp", ".internal", ".local", ".lan"),
            )
        )
    if args.mcp_gateway:  # the path from any agent to the company's MCP servers (M8)
        from .adapters.mcp_gateway import McpGatewayAdapter

        servers = dict(entry.split("=", 1) for entry in args.mcp_server if "=" in entry)
        if not servers:
            print("--mcp-gateway needs at least one --mcp-server NAME=URL", file=sys.stderr)
            return 2
        adapters.append(
            McpGatewayAdapter(
                args.mcp_gateway, servers, enforce=not args.mcp_monitor, user_header=args.mcp_user_header
            )
        )
    if args.openclaw_audit_proxy:  # team gateway: who approved / stopped what (M5b)
        if not args.audit_trusted_peer:
            print(
                "--openclaw-audit-proxy needs --audit-trusted-peer (the identity proxy's IP)", file=sys.stderr
            )
            return 2
        from .adapters.openclaw_audit_proxy import OpenClawAuditProxyAdapter

        adapters.append(
            OpenClawAuditProxyAdapter(
                args.openclaw_audit_proxy, args.openclaw_audit_upstream, args.audit_trusted_peer
            )
        )
    if args.replay:
        adapters.append(ReplayAdapter(args.replay, delay=args.replay_delay))
    if not adapters and args.no_local_api:
        print("nothing to do: pass --openclaw, --replay, a proxy, or keep the local API on", file=sys.stderr)
        return 2
    from .registry import PluginRegistry

    plugins = PluginRegistry(state_path=home.root / "plugin-state.json")  # survives restarts
    from .adapters.openclaw_people import OpenClawPeople

    people = OpenClawPeople(state_path=home.root / "openclaw-people.json")  # team gateway attribution
    ctx = AdapterContext(
        sensor, user_id=args.user, hostname=socket.gethostname(), plugins=plugins, people=people
    )
    local_api = None
    if not args.no_local_api and sys.platform == "win32":
        from .plugin_api import ENDPOINT_FILE, LocalApiServer

        # No unix sockets in asyncio on Windows: loopback TCP + a token in the user's profile (M12).
        local_api = LocalApiServer(ctx, home.root / ENDPOINT_FILE, tcp=True)
    elif not args.no_local_api:
        from .plugin_api import LocalApiServer

        sock = args.socket or home.root / "sga.sock"
        if len(str(sock).encode()) > 100:  # AF_UNIX path limit (104 on macOS, 108 on Linux)
            print(f"socket path too long for a unix socket: {sock} (use --socket)", file=sys.stderr)
            return 2
        local_api = LocalApiServer(ctx, sock)
    daemon = Daemon(
        sensor,
        adapters,
        ctx,
        sync_interval=args.sync_interval,
        flush_interval=args.flush_interval,
        local_api=local_api,
    )

    async def main_task() -> None:
        if args.duration:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(daemon.run(), args.duration)
        else:
            await daemon.run()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main_task())
    s = sensor.spool.stats()
    print(f"stopped; {s['pending_events']} events, {s['pending_findings']} findings still queued")
    return 0


def _cmd_evaluate(home: SensorHome, args: argparse.Namespace) -> int:
    """Degraded path for the OpenClaw plugin when the daemon is unreachable: judge one request
    (JSON on stdin) with the signed policy cache only — no network, no sequence/rate state."""
    import json

    from .adapters.base import AdapterContext
    from .plugin_api import judge

    try:
        req = json.loads(sys.stdin.read())
        sensor = Sensor(home)
    except (ValueError, SensorError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 3
    if not sensor.load_cached_policy():
        print(json.dumps({"ok": False, "error": "no valid cached policy"}))
        return 3
    ctx = AdapterContext(sensor, user_id=args.user, hostname=socket.gethostname())
    if req.get("op") == "resolution":  # the person's answer, recorded even while the daemon is down
        from .plugin_api import record_resolution

        try:
            record_resolution(ctx, req)
        except ValueError as e:
            print(json.dumps({"ok": False, "error": str(e)}))
            return 3
        print(json.dumps({"ok": True}))
        return 0
    print(json.dumps(judge(ctx, req, labels={"sga_verdict": "degraded"})))
    return 0


def _cmd_claude_code(home: SensorHome, args: argparse.Namespace) -> int:
    from . import claude_code_setup as cc

    if args.action == "install":
        try:
            print(cc.install(home.root, args.user, managed=args.managed, dry_run=args.dry_run))
        except (OSError, RuntimeError) as e:
            hint = " (managed settings need administrator rights)" if args.managed else ""
            print(f"error: {e}{hint}", file=sys.stderr)
            return 1
    elif args.action == "uninstall":
        removed = cc.uninstall()
        print("removed from " + ", ".join(removed) if removed else "not installed")
    else:
        st = cc.status()
        print(f"guard hook   {st['guard']}  (managed: can't be removed; user: removable; missing: none)")
        print(f"defaultMode  {st['default_mode'] or '-'}  bypass disabled: {st['bypass_disabled']}")
    return 0


def _cmd_service(home: SensorHome, args: argparse.Namespace) -> int:
    from . import service

    if args.action == "install":
        run_args: list[str] = ["--user", args.user]
        if args.openclaw:
            run_args += ["--openclaw", args.openclaw]
        try:
            print(service.install(home.root, run_args, dry_run=args.dry_run))
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif args.action == "uninstall":
        print(service.uninstall())
    else:
        print(service.status())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sga-sensor", description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", type=Path, help="state dir (default: $SGA_HOME or ~/.sg-advance)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("enroll", help="register this endpoint with the control plane")
    p.add_argument("--server", required=True)
    p.add_argument("--token", help="enrollment token (or SGA_ENROLL_TOKEN)")
    p.add_argument("--device-id")
    p.add_argument("--pin-key", help="base64 policy public key to require (option B)")
    p.add_argument("--ca-file", type=Path, help="device CA for an https (LAN) control plane (M12)")
    p.add_argument("--ca-sha256", help="expected SHA-256 of --ca-file (from the install command)")
    p.set_defaults(fn=_cmd_enroll)

    sub.add_parser("status", help="show identity, cached policy, spool").set_defaults(fn=_cmd_status)
    sub.add_parser("sync", help="pull policy and flush the spool").set_defaults(fn=_cmd_sync)

    p = sub.add_parser("replay", help="feed AgentEvent JSONL through the sensor")
    p.add_argument("events", nargs="+", type=Path)
    p.add_argument("--all", action="store_true", help="also print events without hits")
    p.add_argument("--no-flush", action="store_true", help="only queue; don't ship")
    p.set_defaults(fn=_cmd_replay)

    p = sub.add_parser("run", help="run the local sensor daemon")
    p.add_argument(
        "--openclaw", nargs="?", const="ws://127.0.0.1:18789", metavar="URL", help="watch an OpenClaw gateway"
    )
    p.add_argument("--observe-only", action="store_true", help="detect and report, never abort runs")
    p.add_argument(
        "--gate-exec", action="store_true", help="answer OpenClaw exec approvals: deny risky shell commands"
    )
    p.add_argument("--capture", type=Path, metavar="JSONL", help="append raw gateway frames (masked) here")
    p.add_argument("--replay", nargs="+", type=Path, metavar="JSONL", help="also replay event files (demo)")
    p.add_argument("--replay-delay", type=float, default=0.0, help="seconds between replayed events")
    p.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser(), help="employee id")
    p.add_argument("--sync-interval", type=float, default=60.0)
    p.add_argument("--flush-interval", type=float, default=5.0)
    p.add_argument("--duration", type=float, default=0.0, help="stop after N seconds (0 = run until Ctrl+C)")
    p.add_argument("--log-level", default="info")
    p.add_argument("--log-file", type=Path, help="write the log here instead of stderr")
    p.add_argument("--socket", type=Path, help="local verdict API socket (default: <home>/sga.sock)")
    p.add_argument("--no-local-api", action="store_true", help="don't serve verdicts to gateway plugins")
    p.add_argument("--egress-proxy", metavar="HOST:PORT", help="run the egress proxy (HTTP + CONNECT)")
    p.add_argument("--mcp-gateway", metavar="HOST:PORT", help="run the MCP gateway (agents use /mcp/<name>)")
    p.add_argument(
        "--mcp-server",
        action="append",
        default=[],
        metavar="NAME=URL",
        help="an approved MCP server (repeatable)",
    )
    p.add_argument("--mcp-monitor", action="store_true", help="MCP gateway records only, never refuses")
    p.add_argument(
        "--mcp-gateway-url",
        help="company MCP gateway agents should use, e.g. http://mcp.corp:18790/mcp/ (flags direct servers)",
    )
    p.add_argument(
        "--mcp-user-header", help="trusted identity header on a shared MCP gateway (e.g. x-forwarded-user)"
    )
    p.add_argument(
        "--egress-enforce",
        action="store_true",
        help="refuse destinations the policy blocks (default: monitor, record only)",
    )
    p.add_argument(
        "--egress-internal-suffix",
        action="append",
        default=[],
        metavar="SUFFIX",
        help="host suffix counted as internal (repeatable; default .corp .internal .local .lan)",
    )
    p.add_argument(
        "--openclaw-audit-proxy",
        metavar="HOST:PORT",
        help="relay identity-proxy WebSockets to the gateway, recording approvals and aborts per person",
    )
    p.add_argument("--openclaw-audit-upstream", default="ws://127.0.0.1:18789", metavar="URL")
    p.add_argument(
        "--audit-trusted-peer",
        action="append",
        default=[],
        metavar="IP",
        help="identity proxy address allowed to connect (repeatable)",
    )
    p.add_argument(
        "--keep-chat-text",
        action="store_true",
        help="send every prompt/reply text to the control plane (default: only those a rule hit)",
    )
    p.add_argument(
        "--openclaw-token-file",
        type=Path,
        help="gateway token file, mode 0600 (default: <home>/openclaw-token)",
    )
    p.add_argument(
        "--openclaw-password-file",
        type=Path,
        help="gateway password file for trusted-proxy team gateways (0600, default <home>/openclaw-password)",
    )
    p.add_argument(
        "--openclaw-config",
        type=Path,
        default=Path("~/.openclaw/openclaw.json"),
        help="OpenClaw config to watch for baseline changes (default: ~/.openclaw/openclaw.json)",
    )
    p.add_argument("--no-openclaw-config", action="store_true", help="don't watch the OpenClaw config")
    p.add_argument("--no-openclaw-integrity", action="store_true", help="don't hash installed OpenClaw code")
    p.add_argument("--integrity-interval", type=float, default=300.0, help="seconds between integrity scans")
    p.add_argument(
        "--no-discovery", action="store_true", help="don't scan this endpoint for agent installs (shadow AI)"
    )
    p.add_argument("--discovery-interval", type=float, default=600.0, help="seconds between install scans")
    p.add_argument(
        "--no-claude-code",
        action="store_true",
        help="don't check Claude Code's hook settings on this endpoint",
    )
    p.set_defaults(fn=_cmd_run)

    p = sub.add_parser("service", help="run the daemon as a background service (macOS launchd, Windows task)")
    p.add_argument("action", choices=["install", "uninstall", "status"])
    p.add_argument(
        "--openclaw", nargs="?", const="ws://127.0.0.1:18789", metavar="URL", help="watch an OpenClaw gateway"
    )
    p.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser(), help="employee id")
    p.add_argument("--dry-run", action="store_true", help="print the service definition, change nothing")
    p.set_defaults(fn=_cmd_service)

    p = sub.add_parser("claude-code", help="put the SG-Advance hook into Claude Code's settings (M6)")
    p.add_argument("action", choices=["install", "uninstall", "status"])
    p.add_argument("--managed", action="store_true", help="company managed settings (needs administrator)")
    p.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser(), help="employee id")
    p.add_argument("--dry-run", action="store_true", help="print the settings, change nothing")
    p.set_defaults(fn=_cmd_claude_code)

    p = sub.add_parser("evaluate", help="judge one plugin request from stdin with the cached policy")
    p.add_argument("--user", default=os.environ.get("SGA_USER") or getpass.getuser(), help="employee id")
    p.set_defaults(fn=_cmd_evaluate)

    args = ap.parse_args(argv)
    home = SensorHome(args.home)
    try:
        return args.fn(home, args)
    except (NotEnrolled, NoPolicy, SensorError, ControlPlaneError, Offline) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

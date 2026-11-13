"""``sga-server``: run the control plane with uvicorn, or manage package manifests.

    sga-server [--host H] [--port P]                     # serve
    sga-server manifest list                             # what the policy vouches for
    sga-server manifest add openclaw@2026.11.3 [--approve] [--by NAME]
    sga-server manifest approve|revoke openclaw@2026.11.3 [--by NAME]
    sga-server manifest pin sg-advance --dir integrations/openclaw-plugin --version 0.1.0
    sga-server manifest skill openclaw-workspace:deploy-notes --current   # after reviewing the skill
    sga-server audit approvals [--user U] [--all] [--limit N]   # what users approved (C)
    sga-server policy scopes                              # common + groups, devices, versions (M9)
    sga-server policy rules [--scope data-team] [--changed]
    sga-server policy group data-team --by me --reason "..."
    sga-server policy assign dev-1 data-team --by me --reason "..."     (--common to leave a group)
    sga-server policy set data-team destructive-sql --response block --by me --reason "..."
    sga-server policy clear data-team destructive-sql --by me --reason "..."
    sga-server policy log [--scope data-team]
    sga-server action block-session team-gateway agent:main:… --by me --reason "..."   (M11)
    sga-server action unblock-session|block-user|unblock-user|abort DEVICE TARGET ...
    sga-server action disable-plugin|disable-skill DEVICE TARGET ...
    sga-server action list [--device D]
    sga-server security list [--all] | approve ID | deny ID --by me --reason "..."   (M11)
    sga-server tls ca | server-cert --host 192.168.0.10 [--host my-mac.local] [--out /lan-tls]   (M12)
    sga-server device list | revoke DEVICE --by me --reason "..."   (M12)

The manifest commands call the admin API (``--server``, default ``$SGA_SERVER`` or
http://127.0.0.1:8000) with ``$SGA_ADMIN_TOKEN``; the token is never printed.
"""

from __future__ import annotations

import argparse
import dataclasses
import secrets
import sys

from .settings import Settings


def _api(server: str, method: str, path: str, body: dict | None = None) -> object:
    import json
    import os
    import urllib.error
    import urllib.request

    token = os.environ.get("SGA_ADMIN_TOKEN")
    if not token:
        raise SystemExit("set SGA_ADMIN_TOKEN")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        server.rstrip("/") + path,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=900) as r:  # noqa: S310 - operator-supplied URL
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}") from e


def _fmt(row: dict) -> str:
    when = (row.get("trusted_after") or "")[:16]
    extra = f"  trusted after {when}" if row["status"] == "cooling" else ""
    if row.get("error"):
        extra = f"  error: {row['error'][:120]}"
    return f"{row['spec']:<40} {row['status']:<9} {row['components']:>3} components{extra}"


def manifest_main(argv: list[str]) -> int:
    import os
    from pathlib import Path

    ap = argparse.ArgumentParser(prog="sga-server manifest", description="package manifests (M5d)")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("list")
    for name in ("add", "approve", "revoke"):
        p = sub.add_parser(name)
        p.add_argument("spec", help="npm name@version")
        p.add_argument("--by", help="who decides (audit trail)")
        if name == "add":
            p.add_argument("--approve", action="store_true", help="approve right after verification")
    p = sub.add_parser("pin", help="vouch for an unpublished in-house plugin by its digest")
    p.add_argument("plugin_id")
    p.add_argument("--dir", type=Path, required=True, help="the plugin directory as installed")
    p.add_argument("--version", default="local")
    p.add_argument("--by")
    p = sub.add_parser("skill", help="approve one agent skill's exact files (by digest)")
    p.add_argument("ref", help="source:name from the inventory, e.g. openclaw-managed:pdf-tools")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", type=Path, help="the skill directory you reviewed")
    g.add_argument("--digest", help="digest you reviewed")
    g.add_argument("--current", action="store_true", help="the digest sensors last reported")
    p.add_argument("--by")
    args = ap.parse_args(argv)

    if args.action == "skill":
        from ..integrity import dir_digest

        body = {"ref": args.ref, "by": args.by, "current": args.current}
        if args.dir or args.digest:
            body["digest"] = dir_digest(args.dir) if args.dir else args.digest
        print(_fmt(_api(args.server, "POST", "/v1/admin/manifests/skill", body)))  # type: ignore[arg-type]
        return 0
    if args.action == "list":
        rows = _api(args.server, "GET", "/v1/admin/manifests")
        for row in rows:  # type: ignore[union-attr]
            print(_fmt(row))
        return 0
    if args.action == "pin":
        from ..integrity import dir_digest

        body = {
            "plugin_id": args.plugin_id,
            "version": args.version,
            "digest": dir_digest(args.dir),
            "by": args.by,
        }
        print(_fmt(_api(args.server, "POST", "/v1/admin/manifests/pin", body)))  # type: ignore[arg-type]
        return 0
    body = {"spec": args.spec, "by": args.by}
    if args.action == "add":
        body["approve"] = args.approve
        print(f"verifying {args.spec} (registry signature, provenance, tarball) ...", file=sys.stderr)
        print(_fmt(_api(args.server, "POST", "/v1/admin/manifests", body)))  # type: ignore[arg-type]
    else:
        print(_fmt(_api(args.server, "POST", f"/v1/admin/manifests/{args.action}", body)))  # type: ignore[arg-type]
    return 0


def audit_main(argv: list[str]) -> int:
    import os
    import urllib.parse

    ap = argparse.ArgumentParser(prog="sga-server audit", description="approval audit")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="what", required=True)
    p = sub.add_parser("approvals", help="answers to pre-execution approval prompts, newest first")
    p.add_argument("--user")
    p.add_argument("--all", action="store_true", help="include denials, timeouts and cancellations")
    p.add_argument("--limit", type=int, default=50)
    args = ap.parse_args(argv)
    query = {"limit": args.limit} | ({"user_id": args.user} if args.user else {})
    if not args.all:
        query["approved"] = "true"
    rows = _api(args.server, "GET", "/v1/admin/approvals?" + urllib.parse.urlencode(query))
    for r in rows:  # type: ignore[union-attr]
        flags = ",".join(f["rule_id"] for f in r["flagged"])
        args_text = ""
        if r.get("held_call"):
            args_text = str(r["held_call"]["arguments"])[:80]
        wait = f"{r['wait_ms'] / 1000:.0f}s" if r.get("wait_ms") is not None else "?"
        print(
            f"{r['ts'][:19]}  {r['user_id']:<12} {r['decision']:<11} {r['tool']:<10} "
            f"sev={r['max_severity'] or '-':<8} wait={wait:<5} via={r['judged_by']:<8} "
            f"rules={','.join(r['rule_ids']) or '-'}  by={r.get('approver') or '?'}"
            f"  {('FLAG ' + flags) if flags else ''}"
        )
        if args_text:
            print(f"    {args_text}")
    return 0


def _who(p: argparse.ArgumentParser) -> None:
    p.add_argument("--by", required=True, help="who makes the change (kept in the change log)")
    p.add_argument("--reason", required=True, help="why (kept in the change log)")


def policy_main(argv: list[str]) -> int:
    import os
    import urllib.parse

    ap = argparse.ArgumentParser(prog="sga-server policy", description="policy groups and overrides (M9)")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scopes", help="common policy and groups")
    p = sub.add_parser("rules", help="effective rules of a scope")
    p.add_argument("--scope", default="common")
    p.add_argument("--changed", action="store_true", help="only rules with an override")
    p = sub.add_parser("group", help="create a group")
    p.add_argument("name")
    p.add_argument("--description")
    _who(p)
    p = sub.add_parser("assign", help="move a device into a group")
    p.add_argument("device")
    p.add_argument("group", nargs="?")
    p.add_argument("--common", action="store_true", help="leave any group: common policy only")
    _who(p)
    p = sub.add_parser("set", help="override a rule in a scope (groups: stricter only)")
    p.add_argument("scope")
    p.add_argument("rule")
    on = p.add_mutually_exclusive_group()
    on.add_argument("--enable", dest="enabled", action="store_const", const=True)
    on.add_argument("--disable", dest="enabled", action="store_const", const=False)
    p.add_argument(
        "--response", help="allow|alert|require_approval|security_approval|block|abort_session|quarantine"
    )
    p.add_argument("--allow", help="allowlist entries, comma separated (allowlist rules only)")
    _who(p)
    p = sub.add_parser("clear", help="remove an override (back to the layer below)")
    p.add_argument("scope")
    p.add_argument("rule")
    _who(p)
    p = sub.add_parser("log", help="policy change log, newest first")
    p.add_argument("--scope")
    p.add_argument("--limit", type=int, default=30)
    args = ap.parse_args(argv)
    who = {"by": getattr(args, "by", None), "reason": getattr(args, "reason", None)}

    if args.cmd == "scopes":
        doc = _api(args.server, "GET", "/v1/admin/policy/scopes")
        print(f"revision {doc['revision']}")  # type: ignore[index]
        for sc in doc["scopes"]:  # type: ignore[index]
            print(
                f"{sc['name']:<16} devices={sc['devices']:<3} overrides={sc['overrides']:<3} "
                f"{sc['version'][:16]}…"
            )
    elif args.cmd == "rules":
        rows = _api(
            args.server, "GET", "/v1/admin/policy/rules?" + urllib.parse.urlencode({"scope": args.scope})
        )
        for r in rows:  # type: ignore[union-attr]
            changed = r["common_override"] or r["group_override"]
            if args.changed and not changed:
                continue
            e = r["effective"]
            state = "on " if e["enabled"] else "OFF"
            mark = " *" if changed else ""
            allow = f" allow={','.join(e['allow'])}" if e["allow"] is not None and changed else ""
            print(f"{state} {e['response']:<17} {r['id']}{mark}{allow}")
    elif args.cmd == "group":
        body = {"name": args.name, "description": args.description, **who}
        r = _api(args.server, "POST", "/v1/admin/policy/groups", body)
        print(f"group {args.name} created (revision {r['revision']})")  # type: ignore[index]
    elif args.cmd == "assign":
        if bool(args.group) == args.common:
            raise SystemExit("give a group or --common")
        r = _api(args.server, "PUT", f"/v1/admin/devices/{args.device}/group", {"group": args.group, **who})
        print(f"{args.device} → {args.group or 'common'} (revision {r['revision']})")  # type: ignore[index]
    elif args.cmd == "set":
        body = {"scope": args.scope, "rule_id": args.rule, **who}
        if args.enabled is not None:
            body["enabled"] = args.enabled
        if args.response:
            body["response"] = args.response
        if args.allow is not None:
            body["allow"] = [a.strip() for a in args.allow.split(",") if a.strip()]
        r = _api(args.server, "PUT", "/v1/admin/policy/overrides", body)
        print(f"{args.scope}/{args.rule} set (revision {r['revision']}, version {r['version'][:16]}…)")  # type: ignore[index]
    elif args.cmd == "clear":
        body = {"scope": args.scope, "rule_id": args.rule, **who}
        r = _api(args.server, "POST", "/v1/admin/policy/overrides/clear", body)
        print(f"{args.scope}/{args.rule} cleared (revision {r['revision']})")  # type: ignore[index]
    else:
        q = {"limit": args.limit} | ({"scope": args.scope} if args.scope else {})
        log = _api(args.server, "GET", "/v1/admin/policy/changes?" + urllib.parse.urlencode(q))
        for c in log:  # type: ignore[union-attr]
            what = c["rule_id"] or c["target"] or ""
            print(
                f"#{c['id']:<4} {c['ts'][:19]} {c['actor']:<18} {c['action']:<15} "
                f"{c['scope'] or '-':<12} {what}"
                f"  {c['before'] or ''} → {c['after'] or ''}  ({c['reason']})"
            )
    return 0


ACTION_COMMANDS = {
    "block-session": "block_session",
    "unblock-session": "unblock_session",
    "block-user": "block_user",
    "unblock-user": "unblock_user",
    "abort": "abort_session",
    "disable-plugin": "disable_plugin",
    "disable-skill": "disable_skill",
}


def action_main(argv: list[str]) -> int:
    import os
    import urllib.parse

    ap = argparse.ArgumentParser(prog="sga-server action", description="remote response (M11)")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ACTION_COMMANDS:
        p = sub.add_parser(name)
        p.add_argument("device")
        p.add_argument("target", help="session id, user id, plugin id or skill key")
        p.add_argument("--finding", help="the finding that prompted it")
        _who(p)
    p = sub.add_parser("list", help="queued and finished actions, newest first")
    p.add_argument("--device")
    p.add_argument("--limit", type=int, default=30)
    args = ap.parse_args(argv)
    if args.cmd == "list":
        q = {"limit": args.limit} | ({"device_id": args.device} if args.device else {})
        for a in _api(args.server, "GET", "/v1/admin/actions?" + urllib.parse.urlencode(q)):  # type: ignore[union-attr]
            print(
                f"{a['created_at'][:19]} {a['status']:<9} {a['device_id']:<14} {a['action']:<16} "
                f"{a['target']}"
                f"  by={a['created_by']}  {a['result_detail'] or ''}"
            )
        return 0
    body = {
        "device_id": args.device,
        "action": ACTION_COMMANDS[args.cmd],
        "target": args.target,
        "finding_id": args.finding,
        "by": args.by,
        "reason": args.reason,
    }
    a = _api(args.server, "POST", "/v1/admin/actions", body)
    print(
        f"queued {a['action']} {a['target']} on {a['device_id']} ({a['id'][:8]}); "
        "the sensor picks it up in seconds"
    )  # type: ignore[index]
    return 0


def security_main(argv: list[str]) -> int:
    import os
    import urllib.parse

    ap = argparse.ArgumentParser(prog="sga-server security", description="security approval queue (M11)")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list", help="calls waiting for security (with --all: decided and expired too)")
    p.add_argument("--all", action="store_true")
    p.add_argument("--limit", type=int, default=30)
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("id", help="the request id (a prefix from `list` is not enough: give all of it)")
        _who(p)
    args = ap.parse_args(argv)
    if args.cmd == "list":
        q = {"limit": args.limit} | ({} if args.all else {"status": "pending"})
        rows = _api(args.server, "GET", "/v1/admin/security-approvals?" + urllib.parse.urlencode(q))
        for a in rows:  # type: ignore[union-attr]
            print(
                f"{a['id']} {a['created_at'][:19]} {a['status']:<8} {a['outcome'] or '-':<11} "
                f"{a['user_id']:<20} {a['tool']:<10} {','.join(a['rule_ids'])}"
                f"  until {a['expires_at'][11:19]}  {a['arguments_preview'][:80]}"
            )
        return 0
    body = {"decision": args.cmd, "by": args.by, "reason": args.reason}
    a = _api(args.server, "POST", f"/v1/admin/security-approvals/{args.id}/decision", body)
    print(f"{a['status']} {a['tool']} for {a['user_id']}; the device hears it within a second or two")  # type: ignore[index]
    return 0


def tls_main(argv: list[str]) -> int:
    """Run where the control plane's data lives (inside the container: the CA is in /data/ca)."""
    from pathlib import Path

    from ..pki import cert_pem, key_pem
    from . import device_ca

    ap = argparse.ArgumentParser(
        prog="sga-server tls", description="device CA and LAN gateway certificate (M12)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ca", help="print the device CA fingerprint (pinned by the install command)")
    p = sub.add_parser("server-cert", help="issue the LAN gateway's TLS certificate")
    p.add_argument("--host", action="append", required=True, help="LAN IP or name sensors use (repeat)")
    p.add_argument("--out", type=Path, default=Path("/lan-tls"))
    p.add_argument("--days", type=int, default=825)
    args = ap.parse_args(argv)
    ca = device_ca.load_or_create(Settings.from_env().ca_path)
    if args.cmd == "ca":
        print(ca.fingerprint)
        return 0
    cert, key = ca.sign_server(args.host, args.days)
    args.out.mkdir(parents=True, exist_ok=True)
    device_ca._write(args.out / "server.pem", cert_pem(cert), 0o644)  # noqa: SLF001
    device_ca._write(args.out / "server-key.pem", key_pem(key), 0o600)  # noqa: SLF001
    device_ca._write(args.out / "ca.pem", cert_pem(ca.cert), 0o644)  # noqa: SLF001
    print(
        f"wrote {args.out}/server.pem for {', '.join(args.host)} (until {cert.not_valid_after_utc:%Y-%m-%d})"
    )
    print(f"device CA sha256 {ca.fingerprint}")
    return 0


def device_main(argv: list[str]) -> int:
    import os

    ap = argparse.ArgumentParser(prog="sga-server device", description="devices and enrollment tokens (M12)")
    ap.add_argument("--server", default=os.environ.get("SGA_SERVER", "http://127.0.0.1:8000"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="enrolled devices: certificate, last seen, revoked")
    p = sub.add_parser("revoke", help="stop a device for good (its token and certificate)")
    p.add_argument("device")
    _who(p)
    p = sub.add_parser("token", help="create an enrollment token for one PC")
    p.add_argument("--label")
    p.add_argument("--group", help="policy group the device joins (M9)")
    p.add_argument("--ttl-hours", type=float, default=24)
    p = sub.add_parser(
        "install", help="one-time install command for a new Windows PC (paste into PowerShell)"
    )
    p.add_argument("--device-id", help="device id for that PC (default: its computer name)")
    p.add_argument("--user", help="employee id the sensor reports as (default: the Windows user name)")
    p.add_argument("--label")
    p.add_argument("--group", help="policy group the device joins (M9)")
    p.add_argument("--ttl-hours", type=float, default=24)
    sub.add_parser("tokens", help="enrollment tokens and whether they can still be used")
    p = sub.add_parser("revoke-token", help="make an unused enrollment token unusable")
    p.add_argument("id", type=int)
    args = ap.parse_args(argv)
    if args.cmd == "list":
        for d in _api(args.server, "GET", "/v1/admin/devices"):  # type: ignore[union-attr]
            state = f"REVOKED by {d['revoked_by']}" if d["revoked_at"] else "active"
            cert = f"cert until {d['cert_not_after'][:10]}" if d["client_certificate"] else "token only"
            print(f"{d['device_id']:<16} {state:<24} {cert:<22} last seen {(d['last_seen'] or '-')[:19]}")
        return 0
    if args.cmd == "revoke":
        d = _api(
            args.server,
            "POST",
            f"/v1/admin/devices/{args.device}/revoke",
            {"by": args.by, "reason": args.reason},
        )
        print(f"revoked {d['device_id']} at {d['revoked_at'][:19]}; its token and certificate no longer work")  # type: ignore[index]
        return 0
    if args.cmd == "token":
        body = {"label": args.label, "group": args.group, "ttl_hours": args.ttl_hours}
        t = _api(args.server, "POST", "/v1/admin/enrollment-tokens", body)
        print(t["token"])  # type: ignore[index]
        print(f"id {t['id']}, single use, expires {t['expires_at'][:19]}", file=sys.stderr)  # type: ignore[index]
        return 0
    if args.cmd == "install":
        body = {
            k: v
            for k, v in {
                "device_id": args.device_id,
                "user": args.user,
                "label": args.label,
                "group": args.group,
                "ttl_hours": args.ttl_hours,
            }.items()
            if v is not None
        }
        r = _api(args.server, "POST", "/v1/admin/install-command", body)
        print(r["command"])  # type: ignore[index]
        print(
            f"(single use, expires {r['expires_at'][:19]}; installer sha256 {r['installer_sha256'][:16]}…, "  # type: ignore[index]
            f"device CA {r['ca_fingerprint'][:16]}…)",  # type: ignore[index]
            file=sys.stderr,
        )
        return 0
    if args.cmd == "tokens":
        for t in _api(args.server, "GET", "/v1/admin/enrollment-tokens"):  # type: ignore[union-attr]
            print(
                f"#{t['id']:<4} {'usable' if t['usable'] else 'unusable':<9} {t['uses']}/{t['max_uses']} "
                f"until {(t['expires_at'] or '-')[:19]}  {t['label'] or ''}"
            )
        return 0
    _api(args.server, "POST", f"/v1/admin/enrollment-tokens/{args.id}/revoke")
    print(f"enrollment token #{args.id} revoked")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["tls"]:
        return tls_main(argv[1:])
    if argv[:1] == ["device"]:
        return device_main(argv[1:])
    if argv[:1] == ["security"]:
        return security_main(argv[1:])
    if argv[:1] == ["action"]:
        return action_main(argv[1:])
    if argv[:1] == ["policy"]:
        return policy_main(argv[1:])
    if argv[:1] == ["manifest"]:
        return manifest_main(argv[1:])
    if argv[:1] == ["audit"]:
        return audit_main(argv[1:])
    ap = argparse.ArgumentParser(prog="sga-server", description="sg-advance control plane")
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 inside containers")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)

    import uvicorn

    from .app import create_app

    settings = Settings.from_env()
    if not settings.admin_token:
        # Local dev convenience. Compose and real deployments set SGA_ADMIN_TOKEN.
        settings = dataclasses.replace(settings, admin_token=secrets.token_urlsafe(24))
        print(
            f"SGA_ADMIN_TOKEN not set; generated for this run: {settings.admin_token}",
            file=sys.stderr,
        )
    uvicorn.run(create_app(settings), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

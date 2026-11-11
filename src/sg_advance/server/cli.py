"""``sga-server``: run the control plane with uvicorn, or manage package manifests.

    sga-server [--host H] [--port P]                     # serve
    sga-server manifest list                             # what the policy vouches for
    sga-server manifest add openclaw@2026.11.3 [--approve] [--by NAME]
    sga-server manifest approve|revoke openclaw@2026.11.3 [--by NAME]
    sga-server manifest pin sg-advance --dir integrations/openclaw-plugin --version 0.1.0

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
    args = ap.parse_args(argv)

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


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["manifest"]:
        return manifest_main(argv[1:])
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

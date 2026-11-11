"""``sga-server``: run the control plane with uvicorn."""

from __future__ import annotations

import argparse
import dataclasses
import secrets
import sys

from .settings import Settings


def main(argv: list[str] | None = None) -> int:
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

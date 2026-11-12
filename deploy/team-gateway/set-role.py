"""Assign an operator role to a person on the team gateway (``users.setRole``).

OpenClaw maps people to roles only by explicit assignment (or GitHub login), and a person's profile
exists only after their first sign-in. So: sign in once through the proxy, then run

    docker compose exec team-gateway /opt/sga/venv/bin/python /opt/sga/set-role.py secops@corp.test security

Connects as a same-host operator with the gateway password (admin scope is needed to assign roles).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from sg_advance.sensor.adapters.openclaw_gateway import DeviceIdentity, GatewayConnection, GatewayError

URL = os.environ.get("OPENCLAW_URL", "ws://127.0.0.1:18789")


async def main(email: str, role: str) -> int:
    identity = DeviceIdentity.load_or_create(Path.home() / ".sg-advance" / "role-admin-device.json")
    for attempt in range(30):  # right after a (re)start the gateway answers "starting; retry"
        try:
            conn = await GatewayConnection.open(
                URL,
                None,
                scopes=["operator.read", "operator.admin"],
                identity=identity,
                password=os.environ["OPENCLAW_GATEWAY_PASSWORD"],
            )
            break
        except (GatewayError, OSError):
            if attempt == 29:
                raise
            await asyncio.sleep(1)
    try:
        res = await conn.request("users.list", {})
        profiles = (res.get("payload") or {}).get("profiles") or []
        match = [p for p in profiles if email.lower() in [e.lower() for e in p.get("emails") or []]]
        if not match:
            print(f"no profile for {email}: sign in once through the team proxy first", file=sys.stderr)
            return 1
        res = await conn.request("users.setRole", {"profileId": match[0]["id"], "role": role})
        if not res.get("ok"):
            print(f"users.setRole failed: {res.get('error')}", file=sys.stderr)
            return 1
        print(f"{email} -> {role} (their open sessions are reconnected with the new role)")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: set-role.py <email> <role>", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))

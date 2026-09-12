"""Read-only: the two different `use-radius` fields, side by side.

RouterOS has a `use-radius` on `/ip dhcp-server` AND one on
`/ip hotspot profile`, and they mean unrelated things:

  * `/ip dhcp-server use-radius` -- ask a RADIUS server whether to hand out
    a lease, and account for leases. Almost nobody enables this, and this
    platform does not need it: leases are handed out locally from a pool.
    `no` is correct here.

  * `/ip hotspot profile use-radius` -- check the credential a guest types
    into the captive portal against RADIUS. This is the one that decides
    whether an OTP, voucher or password can ever succeed. `no` here means
    the portal renders and can authenticate nobody.

Printed together so the two are not confused for each other.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"


async def load(host: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        return await conn.fetchrow(
            "SELECT name, api_username, api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
    finally:
        await conn.close()


def main() -> int:
    router = asyncio.run(load(HOST))
    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=30,
    )
    try:
        print("=== /ip dhcp-server  (leases -- `no` is CORRECT here) ===")
        for r in api.path("ip", "dhcp-server"):
            print(f"  {str(r.get('name')):<18} interface={str(r.get('interface')):<10} "
                  f"use-radius={r.get('use-radius')}")

        print("\n=== /ip hotspot profile  (portal login -- this is the one) ===")
        for r in api.path("ip", "hotspot", "profile"):
            print(f"  {str(r.get('name')):<18} use-radius={r.get('use-radius')!s:<6} "
                  f"login-by={r.get('login-by')!r}")

        print("\n=== which profile each hotspot server uses ===")
        for r in api.path("ip", "hotspot"):
            print(f"  {str(r.get('name')):<18} interface={str(r.get('interface')):<10} "
                  f"profile={r.get('profile')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

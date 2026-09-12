"""Read-only: hotspot IP bindings -- who gets internet without logging in.

A host showing `authorized=False bypassed=True` did not authenticate; it
matched an `/ip hotspot ip-binding` with `type=bypassed`, which skips the
portal entirely. That is a completely different mechanism from the hotspot
profile's own RADIUS login, and the two are easy to confuse when the
customer's experience ("it works") is identical.

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
        print("=== /ip hotspot ip-binding ===")
        rows = list(api.path("ip", "hotspot", "ip-binding"))
        if not rows:
            print("  (none -- nobody is bypassed)")
        for r in rows:
            print(f"  mac={r.get('mac-address')!r} address={r.get('address')!r} "
                  f"type={r.get('type')!r} server={r.get('server')!r} "
                  f"comment={r.get('comment')!r} disabled={r.get('disabled')}")

        print("\n=== /ip hotspot host (all) ===")
        for r in api.path("ip", "hotspot", "host"):
            print(f"  {r.get('address')!r} mac={r.get('mac-address')!r} "
                  f"server={r.get('server')!r} authorized={r.get('authorized')} "
                  f"bypassed={r.get('bypassed')}")

        print("\n=== /ip hotspot active (real portal logins) ===")
        act = list(api.path("ip", "hotspot", "active"))
        if not act:
            print("  (none -- nobody has authenticated through a portal)")
        for r in act:
            print(f"  {r.get('address')!r} user={r.get('user')!r} "
                  f"server={r.get('server')!r} uptime={r.get('uptime')!r}")

        print("\n=== /ip hotspot user (locally defined logins) ===")
        users = list(api.path("ip", "hotspot", "user"))
        if not users:
            print("  (none -- so a login can only come from RADIUS)")
        for r in users:
            print(f"  name={r.get('name')!r} server={r.get('server')!r} "
                  f"comment={r.get('comment')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

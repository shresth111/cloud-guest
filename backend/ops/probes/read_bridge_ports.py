"""Read-only: bridge membership and per-interface state.

An access-mode VLAN takes a physical port untagged. If that port was
carrying the guest LAN, the guest network on it stops working the moment
the VLAN lands -- and nothing in the dashboard says so. This reads which
ports are still in the bridge and what is running.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402


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
    host = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
    router = asyncio.run(load(host))
    api = librouteros.connect(
        host=host,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        print("=== /interface bridge port ===")
        rows = list(api.path("interface", "bridge", "port"))
        if not rows:
            print("  (empty)")
        for r in rows:
            print(f"  interface={r.get('interface')!r} bridge={r.get('bridge')!r} "
                  f"pvid={r.get('pvid')} disabled={r.get('disabled')}")

        print("\n=== /interface (ethernet) ===")
        for r in api.path("interface"):
            if str(r.get("type", "")) not in ("ether", "bridge", "vlan"):
                continue
            print(f"  name={r.get('name')!r} type={r.get('type')!r} "
                  f"running={r.get('running')} disabled={r.get('disabled')}")

        print("\n=== /ip hotspot ===")
        hs = list(api.path("ip", "hotspot"))
        if not hs:
            print("  (empty)")
        for r in hs:
            print(f"  name={r.get('name')!r} interface={r.get('interface')!r} "
                  f"profile={r.get('profile')!r} disabled={r.get('disabled')}")

        print("\n=== /ip hotspot active (live guests) ===")
        act = list(api.path("ip", "hotspot", "active"))
        print(f"  {len(act)} active session(s)")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

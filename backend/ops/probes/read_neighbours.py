"""Read-only: ARP and discovered neighbours, per interface.

Answers the one question a port-mode change cannot be judged without: what
is physically attached to the port an access VLAN just took.

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
        print("=== /ip arp ===")
        rows = list(api.path("ip", "arp"))
        if not rows:
            print("  (empty)")
        for r in rows:
            print(f"  address={r.get('address')!r} mac={r.get('mac-address')!r} "
                  f"interface={r.get('interface')!r} dynamic={r.get('dynamic')} "
                  f"complete={r.get('complete')}")

        print("\n=== /ip neighbor (LLDP/MNDP discovery) ===")
        try:
            nb = list(api.path("ip", "neighbor"))
        except Exception as exc:  # noqa: BLE001
            print(f"  <unreadable: {exc}>")
            nb = []
        if not nb:
            print("  (none)")
        for r in nb:
            print(f"  interface={r.get('interface')!r} address={r.get('address')!r} "
                  f"mac={r.get('mac-address')!r} identity={r.get('identity')!r} "
                  f"platform={r.get('platform')!r} board={r.get('board')!r}")

        print("\n=== /interface ethernet (link speed tells you what's plugged) ===")
        for r in api.path("interface", "ethernet"):
            print(f"  {r.get('name')!r} running={r.get('running')} "
                  f"speed={r.get('speed')!r} mac={r.get('mac-address')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

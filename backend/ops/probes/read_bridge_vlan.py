"""Read-only: the bridge's own VLAN settings and its VLAN table.

`vlan-filtering` is the single switch that decides whether a virtual
`/interface vlan` on that bridge can ever receive client traffic. With it
off the bridge ignores 802.1Q tags entirely, so the VLAN interface exists
and serves nobody.

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
        print("=== /interface bridge ===")
        for r in api.path("interface", "bridge"):
            print(f"  name={r.get('name')!r} vlan-filtering={r.get('vlan-filtering')} "
                  f"pvid={r.get('pvid')} protocol-mode={r.get('protocol-mode')!r}")

        print("\n=== /interface bridge vlan ===")
        rows = list(api.path("interface", "bridge", "vlan"))
        if not rows:
            print("  (empty -- no VLAN table entries at all)")
        for r in rows:
            print(f"  bridge={r.get('bridge')!r} vlan-ids={r.get('vlan-ids')!r} "
                  f"tagged={r.get('tagged')!r} untagged={r.get('untagged')!r} "
                  f"dynamic={r.get('dynamic')}")

        print("\n=== /interface ethernet switch (offload capability) ===")
        try:
            for r in api.path("interface", "ethernet", "switch"):
                print(f"  name={r.get('name')!r} type={r.get('type')!r}")
        except Exception as exc:  # noqa: BLE001
            print(f"  <unreadable: {exc}>")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

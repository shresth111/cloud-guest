"""Read-only: what is physically attached, by MAC, per bridge port.

ARP only fills once a device speaks IP, and neighbour discovery only if it
runs LLDP/MNDP. The bridge's own learned-MAC table needs neither -- a device
that has sent a single frame is in it. That is the way to identify what is on
a port when it has taken no address.

Also resolves the OUI prefix so the vendor is named rather than guessed.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"

# Just the prefixes that matter for identifying gear on this fleet. Named
# rather than guessed; anything unlisted is reported as unknown rather than
# assumed.
OUI = {
    "04:F4:1C": "Routerboard/MikroTik",
    "48:8F:5A": "Routerboard/MikroTik",
    "2C:C8:1B": "Routerboard/MikroTik",
    "C0:3A:55": "TP-Link",
    "C2:3A:55": "TP-Link (locally administered)",
    "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link",
    "98:DA:C4": "TP-Link",
    "B0:BE:76": "TP-Link",
    "60:32:B1": "TP-Link",
    "1C:61:B4": "TP-Link",
}


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


def vendor_of(mac: str) -> str:
    return OUI.get(str(mac).upper()[:8], "unknown vendor")


def main() -> int:
    router = asyncio.run(load(HOST))
    if router is None:
        print(f"no router at {HOST}")
        return 2
    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=20,
    )
    try:
        print("=== /interface bridge host (learned MACs) ===")
        rows = list(api.path("interface", "bridge", "host"))
        if not rows:
            print("  (empty -- the bridge has learned no MAC at all)")
        for r in rows:
            mac = r.get("mac-address")
            print(f"  mac={mac!r} on={r.get('on-interface')!r} "
                  f"bridge={r.get('bridge')!r} local={r.get('local')} "
                  f"dynamic={r.get('dynamic')}  [{vendor_of(mac)}]")

        print("\n=== /interface ethernet (link + own MAC) ===")
        for r in api.path("interface", "ethernet"):
            print(f"  {str(r.get('name')):<8} running={r.get('running')} "
                  f"mac={r.get('mac-address')!r}")

        print("\n=== /ip arp ===")
        arp = list(api.path("ip", "arp"))
        if not arp:
            print("  (empty)")
        for r in arp:
            mac = r.get("mac-address")
            print(f"  {r.get('address')!r} mac={mac!r} "
                  f"if={r.get('interface')!r}  [{vendor_of(mac)}]")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

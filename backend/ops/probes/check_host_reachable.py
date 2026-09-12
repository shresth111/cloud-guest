"""Read-only: can the router reach a given host, and why not if it cannot.

Pings from the router itself, then shows the ARP entry, the bridge MAC table
row for that MAC, and every address the router carries -- because "cannot
reach 10.5.50.252" has several different causes and the address list is what
separates them.

Also lists the subnets already on the device, which is what a VLAN's
"subnet overlap" refusal is checked against.

  check_host_reachable.py [target-ip]
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
TARGET = _args[0] if _args else "10.5.50.252"


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
    if router is None:
        print(f"no router at {HOST}")
        return 2
    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=60,
    )
    try:
        print(f"=== ping {TARGET} from the router ===")
        replies, lost = 0, 0
        try:
            for row in api("/ping", address=TARGET, count="4"):
                got = row.get("received")
                ttl = row.get("ttl")
                t = row.get("time")
                print(f"  received={got!r} ttl={ttl!r} time={t!r} "
                      f"status={row.get('status')!r}")
                if str(got) not in ("0", "None", ""):
                    replies += 1
                else:
                    lost += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ping unavailable: {type(exc).__name__}: {exc}")
        print(f"  -> {replies} reply/replies, {lost} without one")

        print("\n=== /ip arp ===")
        arp = list(api.path("ip", "arp"))
        if not arp:
            print("  (empty)")
        for r in arp:
            mark = "  <-- target" if str(r.get("address")) == TARGET else ""
            print(f"  {r.get('address')!r} mac={r.get('mac-address')!r} "
                  f"if={r.get('interface')!r} complete={r.get('complete')}{mark}")

        print("\n=== /interface bridge host ===")
        for r in api.path("interface", "bridge", "host"):
            print(f"  mac={r.get('mac-address')!r} on={r.get('on-interface')!r} "
                  f"local={r.get('local')}")

        print("\n=== every address the router carries ===")
        print("    (a VLAN whose subnet overlaps any of these is refused)")
        for r in api.path("ip", "address"):
            print(f"  {str(r.get('address')):<20} on {str(r.get('interface')):<14} "
                  f"disabled={r.get('disabled')} invalid={r.get('invalid')} "
                  f"comment={r.get('comment')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

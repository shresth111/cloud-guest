"""Why is the AP invisible? Discovery settings first, then a short sniff.

`/ip neighbor` is empty for ether2 and `/ip arp` has nothing on the bridge,
yet the port receives a few packets every ten seconds. Something is talking
and the router is not recording who.

Two possible reasons, checked in order:

  1. Neighbour discovery is not enabled on that interface, so LLDP/MNDP
     frames from the AP are never turned into a neighbour entry. Read-only
     to establish -- `/ip neighbor discovery-settings`.
  2. The AP sends nothing that identifies itself. A short packet capture on
     ether2 settles that: whatever it does send is visible there, with its
     source address if it has one.

The sniffer writes only to its own settings (filter and memory limit) and is
stopped again in a `finally`. It captures to memory, not to a file, so
nothing is left on the device's storage.
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
WATCH = "ether2"
SECONDS = 25


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
        timeout=90,
    )
    started = False
    try:
        print("=== /ip neighbor discovery-settings ===")
        try:
            for r in api.path("ip", "neighbor", "discovery-settings"):
                print(f"  discover-interface-list={r.get('discover-interface-list')!r} "
                      f"protocol={r.get('protocol')!r} "
                      f"lldp-med-net-policy-vlan={r.get('lldp-med-net-policy-vlan')!r}")
        except Exception as exc:  # noqa: BLE001
            print(f"  <unreadable: {exc}>")

        print("\n=== /interface list member (which lists exist) ===")
        try:
            for r in api.path("interface", "list", "member"):
                print(f"  list={r.get('list')!r} interface={r.get('interface')!r}")
        except Exception as exc:  # noqa: BLE001
            print(f"  <unreadable: {exc}>")

        print(f"\n=== sniffing {WATCH} for {SECONDS}s ===")
        api.path("tool", "sniffer").update(
            **{
                "filter-interface": WATCH,
                "memory-limit": "1024",
                "file-name": "",
                "filter-stream": "no",
            }
        )
        api("/tool/sniffer/start")
        started = True
        time.sleep(SECONDS)
        api("/tool/sniffer/stop")
        started = False

        rows = list(api.path("tool", "sniffer", "packet"))
        print(f"captured {len(rows)} packet(s)")
        seen_src = {}
        for r in rows[:60]:
            src = r.get("src-address")
            dst = r.get("dst-address")
            proto = r.get("ip-protocol") or r.get("protocol")
            vlan = r.get("vlan-id")
            print(f"  src={src!r} dst={dst!r} proto={proto!r} "
                  f"vlan-id={vlan!r} size={r.get('size')!r}")
            if src:
                seen_src[str(src)] = seen_src.get(str(src), 0) + 1

        print("\nsource addresses seen:", seen_src or "none")
        vlans = {
            str(r.get("vlan-id")) for r in rows if r.get("vlan-id") not in (None, "")
        }
        print("VLAN ids seen on the wire:",
              sorted(vlans) if vlans else "none (all untagged)")
        return 0
    finally:
        if started:
            try:
                api("/tool/sniffer/stop")
                print("\nsniffer stopped in cleanup")
            except Exception as exc:  # noqa: BLE001
                print(f"\nSNIFFER STOP FAILED: {exc}")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

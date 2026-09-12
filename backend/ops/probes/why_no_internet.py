"""Why a pushed VLAN hands out no internet: check every hop in order.

A VLAN needs four separate things before a client on it reaches the
internet, and this platform models three of them as independent switches, so
a VLAN can be "pushed successfully" with any of them missing:

  1. the interface and its address        (always written)
  2. tagged frames actually arriving      (the AP's job)
  3. a DHCP server, so the client gets an address   (`enable_hotspot`)
  4. a NAT masquerade, so its subnet can leave      (`nat_enabled`)

Reports each, in that order, so the first missing one is obvious rather than
guessed at.

Writes nothing.

  why_no_internet.py [vlan-interface-name]
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
VLAN_IF = _args[0] if _args else "vlan12"
GAP = 8


async def load(host: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router = await conn.fetchrow(
            "SELECT id, name, api_username, api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
        vlans = await conn.fetch(
            "SELECT name, vlan_id, cidr, enable_hotspot, nat_enabled, "
            "device_push_status FROM vlans "
            "WHERE router_id = $1 AND is_deleted = false",
            router["id"],
        )
        return router, vlans
    finally:
        await conn.close()


def rx_of(api, name):
    for r in api.path("interface"):
        if str(r.get("name")) == name:
            try:
                return int(r.get("rx-packet") or 0)
            except (TypeError, ValueError):
                return 0
    return None


def main() -> int:
    router, vlans = asyncio.run(load(HOST))
    print(f"router={router['name']}  checking {VLAN_IF}\n")

    print("=== the switches, as the database has them ===")
    for v in vlans:
        print(f"  {v['name']!r} vlan_id={v['vlan_id']} cidr={v['cidr']!r} "
              f"enable_hotspot={v['enable_hotspot']} nat_enabled={v['nat_enabled']} "
              f"push={v['device_push_status']!r}")

    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=40,
    )
    try:
        addr = [
            str(r.get("address")) for r in api.path("ip", "address")
            if str(r.get("interface")) == VLAN_IF
        ]
        print(f"\n1. interface + address     : {addr or 'MISSING'}")

        before = rx_of(api, VLAN_IF)
        if before is None:
            print(f"2. tagged frames arriving  : no interface named {VLAN_IF}")
        else:
            time.sleep(GAP)
            after = rx_of(api, VLAN_IF)
            delta = after - before
            seen_before = "some, but none now" if after else "NONE"
            verdict = "YES" if delta > 0 else seen_before
            print(f"2. tagged frames arriving  : {verdict} "
                  f"(rx-packet {after}, +{delta} in {GAP}s)")

        servers = [
            r for r in api.path("ip", "dhcp-server")
            if str(r.get("interface")) == VLAN_IF
        ]
        print(f"3. DHCP server on it       : "
              f"{[str(r.get('name')) for r in servers] or 'MISSING'}")

        nat = []
        for r in api.path("ip", "firewall", "nat"):
            if str(r.get("action")) == "masquerade":
                nat.append(
                    f"src={r.get('src-address')} out={r.get('out-interface')} "
                    f"comment={r.get('comment')!r}"
                )
        print(f"4. NAT masquerade rules    : {nat or 'NONE AT ALL'}")

        print("\n--- what that means ---")
        if not addr:
            print("  The interface has no address. Nothing else can work.")
        elif before is not None and rx_of(api, VLAN_IF) == 0:
            print("  No tagged frame has EVER arrived on this interface, so no")
            print("  client is on this VLAN yet. Fix that before anything else:")
            print("  the AP has to tag this VLAN id on its uplink, and a device")
            print("  has to join that SSID.")
        elif not servers:
            print("  Frames arrive but there is no DHCP server on this VLAN, so a")
            print("  client gets no address and cannot do anything. This VLAN was")
            print("  created with the captive portal OFF, and the portal is what")
            print("  creates the pool and the DHCP server.")
        elif not nat:
            print("  A client can get an address but its subnet is not NATed, so")
            print("  packets leave with a private source and die upstream. That is")
            print("  the `nat_enabled` switch, and it defaults to off.")
        else:
            print("  All four are present -- look further out (upstream, DNS).")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

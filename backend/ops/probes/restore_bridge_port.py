"""Put a physical port back into the bridge, and drop the address an access
VLAN gave it.

`delete_vlan` deliberately does not do the first half -- its own docstring
says which bridge the port belonged to was never recorded, so it leaves the
port out of every bridge holding no address. That is safe in the abstract
and wrong when the port was carrying the guest network: the hotspot is bound
to the bridge, and a port outside it serves nobody.

Touches exactly two things: the named port's bridge membership, and an
address on that port matching the one given. Nothing else is written, and
the port's siblings are read only to copy their `pvid`.

Default is a DRY RUN. Pass --apply to write.

  restore_bridge_port.py <router-ip> <port> <bridge> [<address-to-remove>] [--apply]
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

args = [a for a in sys.argv[1:] if a != "--apply"]
APPLY = "--apply" in sys.argv
HOST = args[0] if args else "10.20.0.14"
PORT = args[1] if len(args) > 1 else "ether2"
BRIDGE = args[2] if len(args) > 2 else "bridge"
DROP_ADDRESS = args[3] if len(args) > 3 else None


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
        timeout=15,
    )
    try:
        ports = list(api.path("interface", "bridge", "port"))
        members = {str(p.get("interface")): p for p in ports}
        siblings = [p for i, p in members.items() if str(p.get("bridge")) == BRIDGE]
        pvid = str(siblings[0].get("pvid")) if siblings else "1"

        print(f"router={router['name']} host={HOST}")
        in_bridge = sorted(
            i for i, p in members.items() if str(p.get("bridge")) == BRIDGE
        )
        print(f"bridge {BRIDGE!r} currently has: {in_bridge}")
        print(f"pvid copied from siblings: {pvid}")

        already = PORT in members
        print(f"\n{PORT} in a bridge already: {already}")

        addr_rows = [
            r for r in api.path("ip", "address")
            if str(r.get("interface")) == PORT
            and (DROP_ADDRESS is None or str(r.get("address")) == DROP_ADDRESS)
        ]
        print(f"addresses on {PORT} matching: "
              f"{[str(r.get('address')) for r in addr_rows] or '(none)'}")

        if already and not addr_rows:
            print("\nnothing to do")
            return 0

        print("\nplan:")
        for r in addr_rows:
            print(f"  remove /ip address {r.get('address')} from {PORT}")
        if not already:
            print(f"  add {PORT} to bridge {BRIDGE} with pvid={pvid}")

        if not APPLY:
            print("\nDRY RUN -- nothing written. Re-run with --apply.")
            return 0

        # Address first: a bridge port holding a stray address of its own is
        # a confusing half-state, and the port is already isolated, so there
        # is no connectivity to protect in between.
        for r in addr_rows:
            api.path("ip", "address").remove(r[".id"])
            print(f"removed address {r.get('address')}")
        if not already:
            api.path("interface", "bridge", "port").add(
                interface=PORT, bridge=BRIDGE, pvid=pvid
            )
            print(f"added {PORT} to {BRIDGE}")

        print("\nafter:")
        for p in api.path("interface", "bridge", "port"):
            print(f"  {p.get('interface')} -> {p.get('bridge')} pvid={p.get('pvid')}")
        for r in api.path("ip", "address"):
            if str(r.get("interface")) == PORT:
                print(f"  {PORT} still holds {r.get('address')}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only: what `wireguard_servers.endpoint_host` actually holds, and
the peer/tunnel addresses around it.

Exists because `network_config` passes `server.endpoint_host` as the RADIUS
server address, while the lab router's own `/radius` row holds the hub's
*tunnel* address `10.20.0.1`. RADIUS has to traverse the tunnel -- the hub
matches a client by source address, and the router's src-address is a
tunnel address -- so if `endpoint_host` is a public endpoint, the two are
not the same fact and a push built on it would register a second, wrong
`/radius` row.
"""

import asyncio
import sys

import asyncpg

sys.path.insert(0, "/app")


async def main() -> int:
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        servers = await conn.fetch(
            "SELECT * FROM wireguard_servers"
        )
        print(f"wireguard_servers: {len(servers)}")
        for s in servers:
            print(" ", {k: ("<redacted>" if "key" in k or "secret" in k else v)
                        for k, v in dict(s).items()})

        peers = await conn.fetch(
            "SELECT id, server_id, router_id, tunnel_ip_address "
            "FROM wireguard_peers ORDER BY tunnel_ip_address"
        )
        print(f"\nwireguard_peers: {len(peers)}")
        for p in peers:
            print(" ", dict(p))
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

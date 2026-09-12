"""Read-only: every router, its management address, and whether it has a
WireGuard peer and an active RADIUS NAS row.

Exists because "the other router" turned out to be ambiguous: the tunnel
address 10.20.0.11 belongs to a WireGuard peer whose router_id is one row,
while the router carrying 10.20.0.11 as its *management* address is a
different, seeded demo row. Before dry-running a device push anywhere, it
is worth knowing which rows are real hardware and which are fixtures.

Writes nothing.
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
        rows = await conn.fetch(
            """
            SELECT r.id, r.name, r.status, r.management_ip_address,
                   r.api_username IS NOT NULL AS has_user,
                   r.api_credentials_encrypted IS NOT NULL AS has_secret,
                   r.is_deleted,
                   p.tunnel_ip_address,
                   n.id AS nas_id, n.device_push_status, n.ip_address AS nas_ip
            FROM routers r
            LEFT JOIN wireguard_peers p ON p.router_id = r.id
            LEFT JOIN radius_nas_clients n
                   ON n.router_id = r.id
                  AND n.is_deleted = false
                  AND n.is_active = true
            ORDER BY r.name
            """
        )
        print(f"routers: {len(rows)}\n")
        for r in rows:
            demo = "DEMO/seed" if str(r["id"]).startswith("deadbeef") else "real?"
            print(f"- {r['name']}")
            print(f"    id={r['id']}  [{demo}]  deleted={r['is_deleted']}")
            print(f"    status={r['status']}  mgmt_ip={r['management_ip_address']}")
            print(f"    creds: user={r['has_user']} secret={r['has_secret']}")
            print(f"    wg tunnel_ip={r['tunnel_ip_address']}")
            print(f"    nas={r['nas_id']} push={r['device_push_status']} "
                  f"nas_ip={r['nas_ip']}")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

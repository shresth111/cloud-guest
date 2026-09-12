"""Read-only DB check: does this router have a RADIUS NAS client row, and
is the config script that carries `/radius incoming set accept=yes` even
rendered for it?

Writes nothing, touches no device.
"""

import asyncio
import sys

import asyncpg

sys.path.insert(0, "/app")


async def main(host: str) -> int:
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router = await conn.fetchrow(
            "SELECT id, name, management_ip_address FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
        if router is None:
            print("NO ROUTER ROW")
            return 2
        print(f"router={router['name']} id={router['id']}")

        cols = await conn.fetch(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'radius_nas_clients' ORDER BY ordinal_position"
        )
        if not cols:
            print("no radius_nas_clients table")
            return 0
        names = [c["column_name"] for c in cols]
        print("radius_nas_clients columns:", ", ".join(names))

        rows = await conn.fetch(
            "SELECT * FROM radius_nas_clients WHERE router_id = $1", router["id"]
        )
        print(f"\nNAS client rows for this router: {len(rows)}")
        for r in rows:
            shown = {
                k: ("<redacted>" if "secret" in k.lower() else v)
                for k, v in dict(r).items()
            }
            print(" ", shown)

        total = await conn.fetchval("SELECT count(*) FROM radius_nas_clients")
        print(f"\nNAS client rows across the whole fleet: {total}")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(
        asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"))
    )

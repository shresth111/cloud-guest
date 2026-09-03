"""Read-only: which rows carry the `deadbeef-` fixture id prefix, and what
created them.

No script in any repository produces these ids -- `git log -S` finds them in
no commit, and the only "deadbeef" in the tree is an unrelated Stripe
signature fixture. This asks the database instead: how wide the fixture set
is, when it was written, and by whom, so "there is no seed script" is
established rather than assumed.

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
        tables = await conn.fetch(
            """
            SELECT c.table_name
            FROM information_schema.columns c
            WHERE c.column_name = 'id'
              AND c.data_type = 'uuid'
              AND c.table_schema = 'public'
            ORDER BY c.table_name
            """
        )
        total = 0
        print("tables carrying deadbeef- fixture rows:\n")
        for t in tables:
            name = t["table_name"]
            try:
                rows = await conn.fetch(
                    f"SELECT id, created_at, created_by, version "  # noqa: S608
                    f"FROM {name} WHERE id::text LIKE 'deadbeef%' "
                    f"ORDER BY id"
                )
            except Exception:  # noqa: BLE001 -- table shapes vary
                continue
            if not rows:
                continue
            total += len(rows)
            print(f"  {name}: {len(rows)}")
            for r in rows[:4]:
                print(f"     {r['id']}  created_at={r['created_at']} "
                      f"created_by={r['created_by']} version={r['version']}")
            if len(rows) > 4:
                print(f"     ... and {len(rows) - 4} more")
        print(f"\ntotal fixture rows: {total}")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

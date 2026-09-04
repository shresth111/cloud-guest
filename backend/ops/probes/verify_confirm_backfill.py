"""Did migration 0112's backfill do what its docstring claims?

It was written and reviewed as unexecuted SQL -- there is no database in the
authoring environment -- so this checks the real one after deploy.

The claim: `confirm_takes_port` is true exactly for rows with
`port_mode='access'` AND `device_pushed_at IS NOT NULL` (their port is
already out of its bridge, so asking now protects nothing and refusing would
break the re-push that is the recovery path), and false everywhere else.

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
        col = await conn.fetchrow(
            "SELECT column_name, data_type, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_name='vlans' AND column_name='confirm_takes_port'"
        )
        print("=== column ===")
        print(f"  {dict(col) if col else 'MISSING -- migration did not apply'}")
        if col is None:
            return 1

        rows = await conn.fetch(
            "SELECT name, vlan_id, port_mode, confirm_takes_port, "
            "device_pushed_at IS NOT NULL AS pushed, is_deleted "
            "FROM vlans ORDER BY vlan_id"
        )
        print(f"\n=== every vlan row ({len(rows)}) ===")
        wrong = []
        for r in rows:
            expected = r["port_mode"] == "access" and r["pushed"]
            ok = bool(r["confirm_takes_port"]) is expected
            if not ok:
                wrong.append(r)
            print(f"  {str(r['name'])[:22]:<24} vlan={r['vlan_id']:<5} "
                  f"mode={r['port_mode']:<7} pushed={r['pushed']!s:<5} "
                  f"confirm={r['confirm_takes_port']!s:<5} "
                  f"deleted={r['is_deleted']!s:<5} {'ok' if ok else 'MISMATCH'}")

        print()
        if wrong:
            print(f"BACKFILL WRONG on {len(wrong)} row(s) -- the docstring's rule "
                  "does not describe the data")
            return 1
        print("backfill matches its stated rule on every row")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

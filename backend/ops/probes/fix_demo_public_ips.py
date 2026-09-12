"""Move seeded demo routers off real, allocated public address space.

``scripts/seed_demo.py`` used to write ``public_ip_address =
49.36.{loc}.{r}``. That is inside ``49.32.0.0/12``, currently allocated to
Reliance Jio Infocomm Limited (confirmed via APNIC RDAP) -- somebody else's
routable addresses, shown in the dashboard as this platform's own
infrastructure.

The seed is fixed, but it is idempotent by serial number: it returns an
existing router untouched rather than updating it, so rows already written
keep the old address until something changes them. This does that.

New addresses come from 198.51.100.0/24 (TEST-NET-2, RFC 5737), matching
what the corrected seed now generates.

Default is a DRY RUN. Pass ``--apply`` to write. Only rows whose
``public_ip_address`` sits inside 49.32.0.0/12 are touched, and only
``public_ip_address`` is written.
"""

import asyncio
import ipaddress
import sys

import asyncpg

sys.path.insert(0, "/app")

APPLY = "--apply" in sys.argv
BAD_NET = ipaddress.ip_network("49.32.0.0/12")
REPLACEMENT_NET = ipaddress.ip_network("198.51.100.0/24")


async def main() -> int:
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        rows = await conn.fetch(
            "SELECT id, name, public_ip_address FROM routers "
            "WHERE public_ip_address IS NOT NULL ORDER BY name"
        )
        taken = {r["public_ip_address"] for r in rows}
        offenders = []
        for r in rows:
            try:
                addr = ipaddress.ip_address(r["public_ip_address"])
            except ValueError:
                continue
            if addr in BAD_NET:
                offenders.append(r)

        if not offenders:
            print("no router carries an address inside "
                  f"{BAD_NET} -- nothing to do")
            return 0

        hosts = (h for h in REPLACEMENT_NET.hosts() if str(h) not in taken)
        plan = []
        for r in offenders:
            new_ip = str(next(hosts))
            taken.add(new_ip)
            plan.append((r, new_ip))

        print(f"{len(plan)} router(s) inside {BAD_NET} "
              "(Reliance Jio Infocomm, per APNIC RDAP):\n")
        for r, new_ip in plan:
            print(f"  {r['name']}")
            print(f"    id={r['id']}")
            print(f"    {r['public_ip_address']}  ->  {new_ip}")

        if not APPLY:
            print("\nDRY RUN -- nothing written. Re-run with --apply to write.")
            return 0

        async with conn.transaction():
            for r, new_ip in plan:
                await conn.execute(
                    "UPDATE routers SET public_ip_address = $1, "
                    "updated_at = now() WHERE id = $2",
                    new_ip,
                    r["id"],
                )
        print(f"\nAPPLIED: {len(plan)} row(s) updated")
        for r, _ in plan:
            check = await conn.fetchrow(
                "SELECT public_ip_address FROM routers WHERE id = $1", r["id"]
            )
            print(f"  {r['name']}: now {check['public_ip_address']}")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

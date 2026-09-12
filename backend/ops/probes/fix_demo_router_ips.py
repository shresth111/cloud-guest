"""Move seeded demo routers off the WireGuard tunnel network.

A demo row carries `management_ip_address = 10.20.0.11`, which is also the
real tunnel address of `ZZ Postdeploy Router`'s WireGuard peer. Two rows,
one address. It is harmless today only because the demo rows have no API
credentials, so a device push refuses before it connects -- but "the wrong
router is protected by having no password" is not a property to rely on.

These rows are fixtures with no seed script in any repository, so this is a
data fix, not a code one.

New addresses come from **192.0.2.0/24 (TEST-NET-1, RFC 5737)**, which is
reserved for documentation and examples and is guaranteed never to be real
infrastructure -- so a demo row can never again collide with a tunnel
address, a guest subnet, or anything else this platform allocates.

Default is a DRY RUN. Pass `--apply` to write.

Only rows whose id begins with `deadbeef` **and** whose management address
falls inside the active tunnel network are touched. Nothing else is read
for permission, and no other column is written.
"""

import asyncio
import ipaddress
import sys

import asyncpg

sys.path.insert(0, "/app")

APPLY = "--apply" in sys.argv
DEMO_PREFIX = "deadbeef"
REPLACEMENT_NET = ipaddress.ip_network("192.0.2.0/24")


async def main() -> int:
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        server = await conn.fetchrow(
            "SELECT tunnel_network_cidr FROM wireguard_servers "
            "WHERE is_active = true LIMIT 1"
        )
        if server is None:
            print("no active WireGuard server; cannot tell which range collides")
            return 2
        tunnel = ipaddress.ip_network(server["tunnel_network_cidr"], strict=False)
        print(f"tunnel network: {tunnel}")

        rows = await conn.fetch(
            "SELECT id, name, management_ip_address FROM routers "
            "WHERE management_ip_address IS NOT NULL ORDER BY name"
        )

        taken = {
            r["management_ip_address"]
            for r in rows
            if r["management_ip_address"]
        }
        offenders = []
        for r in rows:
            if not str(r["id"]).startswith(DEMO_PREFIX):
                continue
            try:
                addr = ipaddress.ip_address(r["management_ip_address"])
            except ValueError:
                continue
            if addr in tunnel:
                offenders.append(r)

        if not offenders:
            print("\nno demo router sits inside the tunnel network -- nothing to do")
            return 0

        hosts = (h for h in REPLACEMENT_NET.hosts() if str(h) not in taken)
        plan = []
        for r in offenders:
            new_ip = str(next(hosts))
            taken.add(new_ip)
            plan.append((r, new_ip))

        print(f"\n{len(plan)} demo router(s) inside the tunnel network:")
        for r, new_ip in plan:
            print(f"  {r['name']}")
            print(f"    id={r['id']}")
            print(f"    {r['management_ip_address']}  ->  {new_ip}")

        # Name what each colliding address really belongs to, so the fix is
        # visibly targeting the right rows.
        for r, _new_ip in plan:
            peer = await conn.fetchrow(
                "SELECT p.tunnel_ip_address, rt.name FROM wireguard_peers p "
                "JOIN routers rt ON rt.id = p.router_id "
                "WHERE p.tunnel_ip_address = $1",
                r["management_ip_address"],
            )
            if peer is not None:
                print(f"\n  {r['management_ip_address']} is the real tunnel address "
                      f"of '{peer['name']}'")

        if not APPLY:
            print("\nDRY RUN -- nothing written. Re-run with --apply to write.")
            return 0

        async with conn.transaction():
            for r, new_ip in plan:
                await conn.execute(
                    "UPDATE routers SET management_ip_address = $1, "
                    "updated_at = now() WHERE id = $2",
                    new_ip,
                    r["id"],
                )
        print(f"\nAPPLIED: {len(plan)} row(s) updated")

        for r, _ in plan:
            check = await conn.fetchrow(
                "SELECT management_ip_address FROM routers WHERE id = $1", r["id"]
            )
            print(f"  {r['name']}: now {check['management_ip_address']}")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

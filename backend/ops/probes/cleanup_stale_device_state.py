"""Remove leftovers this platform did not put on the router and nothing uses.

Four kinds, each matched narrowly and each explained:

  1. `/ip address` rows RouterOS marks `invalid` -- the interface they name
     no longer exists, so they route nothing. They still blocked VLAN
     subnets until the overlap check learned to skip them.
  2. `/ip address` rows in an explicit remove-list, passed by the operator.
     Not inferred: an address on a live interface may be someone's real
     configuration, so only ones named on the command line go.
  3. `/interface bridge vlan` rows for VLAN ids with no matching
     `/interface vlan` and no bridge port tagged for them -- stale table
     entries that describe nothing.
  4. Nothing else. Firewall rules, NAT, hotspot objects and DHCP are left
     alone entirely.

Default is a DRY RUN. Pass --apply to write.

  cleanup_stale_device_state.py [--apply] [addr-to-remove ...]
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
APPLY = "--apply" in sys.argv
EXTRA = [a for a in sys.argv[1:] if not a.startswith("-")]


def truthy(v) -> bool:
    return v is True or str(v).lower() in ("true", "yes")


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
    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=40,
    )
    try:
        plan = []

        for r in api.path("ip", "address"):
            addr = str(r.get("address"))
            if truthy(r.get("invalid")):
                plan.append((
                    ("ip", "address"), r[".id"],
                    f"{addr} on {r.get('interface')} -- invalid, interface gone",
                ))
            elif addr in EXTRA:
                plan.append((
                    ("ip", "address"), r[".id"],
                    f"{addr} on {r.get('interface')} -- named on the command line",
                ))

        vlan_ids = {str(r.get("vlan-id")) for r in api.path("interface", "vlan")}
        for r in api.path("interface", "bridge", "vlan"):
            ids = str(r.get("vlan-ids") or "")
            tagged = str(r.get("tagged") or "")
            untagged = str(r.get("untagged") or "")
            ports = [
                p
                for p in (tagged + "," + untagged).split(",")
                if p and p != "bridge"
            ]
            stale = (
                ids
                and ids not in vlan_ids
                and not ports
                and not truthy(r.get("dynamic"))
            )
            if stale:
                plan.append((
                    ("interface", "bridge", "vlan"), r[".id"],
                    f"bridge vlan-ids={ids} tagged={tagged!r} untagged={untagged!r} "
                    "-- no such /interface vlan and no port tagged for it",
                ))

        if not plan:
            print("nothing stale to remove")
            return 0

        print(f"router={router['name']}\n{len(plan)} row(s) to remove:\n")
        for path, _rid, why in plan:
            print(f"  /{'/'.join(path)}   {why}")

        if not APPLY:
            print("\nDRY RUN -- nothing written. Re-run with --apply.")
            return 0

        for path, rid, why in plan:
            try:
                api.path(*path).remove(rid)
                print(f"removed: {why}")
            except Exception as exc:  # noqa: BLE001
                print(f"FAILED  {why}: {exc}")

        print("\n=== /ip address after ===")
        for r in api.path("ip", "address"):
            print(f"  {r.get('address')!r} on {r.get('interface')!r} "
                  f"invalid={r.get('invalid')}")
        print("=== /interface bridge vlan after ===")
        rows = list(api.path("interface", "bridge", "vlan"))
        if not rows:
            print("  (empty)")
        for r in rows:
            print(f"  vlan-ids={r.get('vlan-ids')!r} tagged={r.get('tagged')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only: what a VLAN actually became, on the device and in the database.

A VLAN row, its DHCP pool row, and the RouterOS objects they should have
produced are three separate things, and this platform's whole class of bug
is one of them existing while another does not. Prints all three side by
side rather than trusting any single one.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402


async def load(host: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router = await conn.fetchrow(
            "SELECT id, name, api_username, api_credentials_encrypted "
            "FROM routers WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
        vlans = await conn.fetch(
            "SELECT * FROM vlans WHERE router_id = $1 AND is_deleted = false "
            "ORDER BY created_at DESC",
            router["id"],
        )
        pools = await conn.fetch(
            "SELECT * FROM dhcp_pools WHERE router_id = $1 AND is_deleted = false "
            "ORDER BY created_at DESC",
            router["id"],
        )
        return router, vlans, pools
    finally:
        await conn.close()


def show(label, rows, keys):
    print(f"\n=== {label} ({len(rows)}) ===")
    if not rows:
        print("  (none)")
    for r in rows:
        d = dict(r)
        print("  " + "  ".join(f"{k}={d.get(k)!r}" for k in keys if k in d))


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
    router, vlans, pools = asyncio.run(load(host))
    print(f"router={router['name']} host={host}")

    show("DB vlans", vlans,
         ["name", "vlan_id", "cidr", "gateway_ip_address", "port_mode",
          "mikrotik_interface_name", "is_enabled", "device_push_status",
          "device_push_error"])
    show("DB dhcp_pools", pools,
         ["name", "vlan_id", "range_start", "range_end", "gateway_ip_address",
          "dns_primary", "is_enabled", "device_push_status",
          "device_push_error"])

    api = librouteros.connect(
        host=host,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        for path, keys in [
            (("interface", "vlan"), ("name", "vlan-id", "interface", "comment")),
            (("ip", "address"), ("address", "interface", "comment")),
            (("ip", "pool"), ("name", "ranges", "comment")),
            (("ip", "dhcp-server"), ("name", "interface", "address-pool",
                                     "lease-time", "disabled", "comment")),
            (("ip", "dhcp-server", "network"), ("address", "gateway",
                                                "dns-server", "comment")),
        ]:
            print(f"\n=== device /{'/'.join(path)} ===")
            rows = list(api.path(*path))
            if not rows:
                print("  (empty)")
            for r in rows:
                print("  " + "  ".join(
                    f"{k}={r.get(k)!r}" for k in keys if r.get(k) not in (None, "")
                ))
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

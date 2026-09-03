"""Read-only: dump every /ip firewall filter rule, grouped by chain.

Writes nothing. Exists to answer one question the T2 listing raised: the two
dynamic `jump` rules at the top of `forward` are hotspot's, and if the chain
they jump to ACCEPTS authenticated guest traffic, a content-filter DROP
appended at the bottom of `forward` never sees that traffic at all -- the
packet is accepted inside the subchain and never returns.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402


async def load_router(host_filter: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        return await conn.fetchrow(
            """
            SELECT management_ip_address, api_username,
                   api_credentials_encrypted, name
            FROM routers
            WHERE management_ip_address = $1
            LIMIT 1
            """,
            host_filter,
        )
    finally:
        await conn.close()


def is_dynamic(row) -> bool:
    v = row.get("dynamic")
    return v is True or str(v).lower() in ("true", "yes")


FIELDS = (
    "action", "jump-target", "chain", "comment", "connection-state",
    "src-address-list", "dst-address-list", "hotspot", "protocol",
    "in-interface", "out-interface", "dst-port",
)


def main():
    row = asyncio.run(load_router(sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"))
    if row is None:
        print("NO ROUTER ROW")
        return 2
    password = decrypt_secret(row["api_credentials_encrypted"])
    print(f"router={row['name']} host={row['management_ip_address']}")

    api = librouteros.connect(
        host=row["management_ip_address"],
        username=row["api_username"],
        password=password,
        port=8728,
        timeout=15,
    )
    try:
        rules = list(api.path("ip", "firewall", "filter"))
        by_chain: dict[str, list] = {}
        for r in rules:
            by_chain.setdefault(str(r.get("chain", "?")), []).append(r)

        for chain, rows in by_chain.items():
            print(f"\n=== chain {chain} ({len(rows)} rules) ===")
            for i, r in enumerate(rows):
                flag = "D" if is_dynamic(r) else " "
                bits = " ".join(
                    f"{k}={r[k]}" for k in FIELDS
                    if k in r and k != "chain" and r[k] not in (None, "")
                )
                print(f"  {i:>3} {flag} {bits}")

        print("\n=== address lists ===")
        seen: dict[str, int] = {}
        for r in api.path("ip", "firewall", "address-list"):
            name = str(r.get("list", "?"))
            seen[name] = seen.get(name, 0) + 1
        for name, count in sorted(seen.items()):
            print(f"  {name}: {count} entries")
        if not seen:
            print("  (none)")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

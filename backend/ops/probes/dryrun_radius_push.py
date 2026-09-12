"""Dry run: exactly what `push_nas_client_to_device` would change on the
lab router, without writing anything.

The push adopts an existing `/radius` row for the same server rather than
adding a second one, which means it will also overwrite that row's
`secret` with the one in this platform's database. The row on the lab
router was written by hand. If the two secrets differ, the push would
realign the router with the hub -- or break a working login, depending on
which of the two the hub's own `client{}` stanza agrees with. That is worth
knowing before writing, not after.

Writes nothing. Secrets are compared, never printed.
"""

import asyncio
import hashlib
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402


def fingerprint(value: str | None) -> str:
    if not value:
        return "<empty>"
    return hashlib.sha256(value.encode()).hexdigest()[:12]


async def load(host: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router = await conn.fetchrow(
            "SELECT id, name, management_ip_address, api_username, "
            "api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
        nas = await conn.fetchrow(
            "SELECT id, ip_address, shared_secret_encrypted "
            "FROM radius_nas_clients "
            "WHERE router_id = $1 AND is_deleted = false AND is_active = true "
            "LIMIT 1",
            router["id"],
        )
        server = await conn.fetchrow(
            "SELECT tunnel_network_cidr, endpoint_host FROM wireguard_servers "
            "WHERE is_active = true LIMIT 1"
        )
        return router, nas, server
    finally:
        await conn.close()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
    router, nas, server = asyncio.run(load(host))
    if router is None or nas is None or server is None:
        print("missing router, active NAS row, or active WireGuard server")
        return 2

    import ipaddress

    network = ipaddress.ip_network(server["tunnel_network_cidr"], strict=False)
    hub_ip = str(next(network.hosts()))
    our_secret = decrypt_secret(nas["shared_secret_encrypted"])

    print(f"router={router['name']} host={host}")
    print(f"NAS row: ip_address={nas['ip_address']}")
    print(f"hub tunnel address (what we would write): {hub_ip}")
    print(f"endpoint_host (what the old code passed):  {server['endpoint_host']}")

    desired = {
        "service": "hotspot",
        "address": hub_ip,
        "authentication-port": "1812",
        "accounting-port": "1813",
        "src-address": nas["ip_address"],
        "comment": "WyfyGuest RADIUS NAS client",
    }

    api = librouteros.connect(
        host=host,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        matched = None
        for row in api.path("radius"):
            if (str(row.get("service", "")) == "hotspot"
                    and str(row.get("address", "")) == hub_ip):
                matched = row
                break

        print("\n--- /radius ---")
        if matched is None:
            print("  no row for this server -> the push would ADD one:")
            for k, v in desired.items():
                print(f"    {k} = {v}")
            print("    secret = <from DB>", fingerprint(our_secret))
            existing = [
                (r.get("address"), r.get("comment")) for r in api.path("radius")
            ]
            print(f"  existing rows left untouched: {existing}")
        else:
            print(f"  adopting row {matched['.id']} "
                  f"(comment={matched.get('comment')!r})")
            for k, v in desired.items():
                current = str(matched.get(k, ""))
                mark = "same" if current == v else f"CHANGE  {current!r} -> {v!r}"
                print(f"    {k}: {mark}")
            same_secret = str(matched.get("secret", "")) == our_secret
            print(f"    secret: {'same' if same_secret else 'CHANGE'} "
                  f"(device={fingerprint(str(matched.get('secret')))} "
                  f"db={fingerprint(our_secret)})")

        print("\n--- /radius incoming ---")
        for row in api.path("radius", "incoming"):
            print(f"  current: accept={row.get('accept')} port={row.get('port')}")
            print("  would write: accept=yes port=3799")
            break
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

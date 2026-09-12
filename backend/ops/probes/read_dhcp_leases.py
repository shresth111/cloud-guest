"""Read-only: current DHCP leases and hotspot hosts.

After restoring a port to the bridge, the question is whether the device on
it comes back onto the guest network. ARP only fills once it talks IP; a
lease is the earlier and more direct signal.

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
        return await conn.fetchrow(
            "SELECT name, api_username, api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
    finally:
        await conn.close()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
    router = asyncio.run(load(host))
    api = librouteros.connect(
        host=host,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        for path, keys in [
            (("ip", "dhcp-server", "lease"),
             ("address", "mac-address", "host-name", "status", "server", "dynamic")),
            (("ip", "hotspot", "host"),
             ("address", "mac-address", "to-address", "server", "authorized")),
            (("ip", "arp"), ("address", "mac-address", "interface", "complete")),
        ]:
            print(f"\n=== /{'/'.join(path)} ===")
            try:
                rows = list(api.path(*path))
            except Exception as exc:  # noqa: BLE001
                print(f"  <unreadable: {exc}>")
                continue
            if not rows:
                print("  (none)")
            for r in rows:
                print("  " + "  ".join(
                    f"{k}={r.get(k)!r}" for k in keys if r.get(k) not in (None, "")
                ))
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

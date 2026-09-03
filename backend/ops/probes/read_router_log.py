"""Read-only: the router's own log, plus the live state of the guest path.

When "it is not working" needs narrowing, the device's own log is the one
source that says what it thinks happened, in order. Everything else here is
current state for the guest data path: hotspot server, its DHCP server and
pool, and the bridge.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

TAIL = int(sys.argv[2]) if len(sys.argv) > 2 else 40


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
        timeout=20,
    )
    try:
        print(f"=== /log (last {TAIL}) ===")
        rows = list(api.path("log"))
        for r in rows[-TAIL:]:
            print(f"  {r.get('time')} [{r.get('topics')}] {r.get('message')}")
        if not rows:
            print("  (empty)")

        print("\n=== guest path state ===")
        for path, keys in [
            (("ip", "hotspot"),
             ("name", "interface", "profile", "disabled", "invalid")),
            (("ip", "hotspot", "profile"), ("name", "hotspot-address", "dns-name",
                                            "use-radius", "html-directory")),
            (("ip", "dhcp-server"), ("name", "interface", "address-pool",
                                     "disabled", "invalid")),
            (("ip", "pool"), ("name", "ranges")),
            (("interface", "bridge", "port"),
             ("interface", "bridge", "pvid", "disabled", "inactive")),
        ]:
            print(f"\n--- /{'/'.join(path)} ---")
            got = list(api.path(*path))
            if not got:
                print("  (empty)")
            for r in got:
                print("  " + "  ".join(
                    f"{k}={r.get(k)!r}" for k in keys if r.get(k) not in (None, "")
                ))
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

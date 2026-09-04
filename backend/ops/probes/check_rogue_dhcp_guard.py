"""Is there anything watching for a rogue DHCP server on the guest bridge?

A device briefly appeared on the guest bridge announcing `192.168.1.1` -- the
WAN gateway's address -- with an Atheros MAC. That shape is a consumer router
plugged into the guest network in its factory configuration, and the address
it claims is the least of it: such a device usually also serves DHCP. A rogue
DHCP server on the guest bridge hands guests addresses and a gateway that go
nowhere, and it wins whenever it answers first.

RouterOS has `/ip dhcp-server alert` for exactly this: it watches an
interface and logs when a DHCP server other than the ones listed replies.

This reports whether such an alert exists, and what the log already knows.

Writes nothing.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"


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
        print("=== /ip dhcp-server alert ===")
        try:
            rows = list(api.path("ip", "dhcp-server", "alert"))
        except Exception as exc:  # noqa: BLE001
            print(f"  <unreadable: {exc}>")
            rows = []
        if not rows:
            print("  (none -- nothing is watching for a rogue DHCP server)")
        for r in rows:
            print(f"  interface={r.get('interface')!r} "
                  f"valid-server={r.get('valid-server')!r} "
                  f"alert-timeout={r.get('alert-timeout')!r} "
                  f"disabled={r.get('disabled')} "
                  f"unknown-server={r.get('unknown-server')!r}")

        print("\n=== log lines mentioning dhcp/rogue/duplicate ===")
        hits = 0
        for r in api.path("log"):
            msg = str(r.get("message", "")).lower()
            if any(k in msg for k in ("dhcp", "rogue", "duplicate", "conflict")):
                print(f"  {r.get('time')} [{r.get('topics')}] {r.get('message')}")
                hits += 1
        if not hits:
            print("  (nothing in the log buffer)")

        print("\n=== who is on the guest bridge right now ===")
        for r in api.path("interface", "bridge", "host"):
            print(f"  mac={r.get('mac-address')!r} on={r.get('on-interface')!r} "
                  f"local={r.get('local')}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

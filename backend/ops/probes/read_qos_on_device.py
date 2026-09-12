"""Read-only: the two objects a QoS rule becomes on a RouterOS device.

RouterOS realizes QoS as a `/ip firewall mangle` rule that SETS a packet
mark and a `/queue tree` entry that REFERENCES it. Before #118 only the
queue half had a caller, so a push produced a queue pointing at a mark
nothing ever set -- inert, under a badge reading "Applied to your router".

This reads both and reports whether the marks line up, which is the only
thing that makes the pair do anything.

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
            "SELECT name, management_ip_address, api_username, "
            "api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            host,
        )
    finally:
        await conn.close()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
    router = asyncio.run(load(host))
    if router is None:
        print(f"no router at {host}")
        return 2
    api = librouteros.connect(
        host=host,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        marks_set = {}
        print("=== /ip firewall mangle (packet marks) ===")
        found = False
        for row in api.path("ip", "firewall", "mangle"):
            found = True
            mark = row.get("new-packet-mark")
            if mark:
                marks_set[str(mark)] = row.get("comment")
            print(f"  chain={row.get('chain')} action={row.get('action')} "
                  f"proto={row.get('protocol')} dst-port={row.get('dst-port')} "
                  f"dscp={row.get('dscp')} mark={mark} "
                  f"passthrough={row.get('passthrough')} "
                  f"comment={row.get('comment')!r}")
        if not found:
            print("  (empty)")

        print("\n=== /queue tree ===")
        found = False
        for row in api.path("queue", "tree"):
            found = True
            ref = str(row.get("packet-mark") or "")
            verdict = (
                "MARK IS SET by a mangle rule" if ref in marks_set
                else "NO mangle rule sets this mark -- queue is inert"
            )
            print(f"  name={row.get('name')} parent={row.get('parent')} "
                  f"priority={row.get('priority')} packet-mark={ref!r}")
            print(f"      -> {verdict}")
        if not found:
            print("  (empty)")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

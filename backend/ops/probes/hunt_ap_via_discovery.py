"""Make the router listen hard on the AP's port, briefly, and see who answers.

Correction to an earlier guess of mine: `discover-interface-list=static`
already covers `ether2` -- `ether1`'s neighbour entries prove that `static`
is working -- so "add ether2 to the discovery list" would have changed
nothing. Discovery is already on for that port and the AP is simply not
being recorded.

What is still worth testing is whether the AP announces itself at all when
the router actively looks on that port and the bridge. Rather than switching
discovery to `all` (which would also announce this router on the WAN, toward
the upstream TP-Link), this creates a dedicated interface list containing
only `ether2` and `bridge`, points discovery at it for a short window, reads
`/ip neighbor`, and then puts the setting back and deletes the list.

Every change is reverted in a `finally`, including on failure. The original
value of `discover-interface-list` is read first and restored verbatim.
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
LIST_NAME = "cg-discover-tmp"
MEMBERS = ["ether2", "bridge"]
WINDOW = 35


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


def show_neighbours(api, label: str) -> None:
    print(f"\n--- /ip neighbor ({label}) ---")
    rows = list(api.path("ip", "neighbor"))
    if not rows:
        print("    (none)")
    for r in rows:
        print(f"    if={r.get('interface')!r} addr={r.get('address')!r} "
              f"mac={r.get('mac-address')!r} identity={r.get('identity')!r} "
              f"platform={r.get('platform')!r} board={r.get('board')!r} "
              f"version={r.get('version')!r}")


def main() -> int:
    router = asyncio.run(load(HOST))
    if router is None:
        print(f"no router at {HOST}")
        return 2
    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=90,
    )
    original = None
    settings_id = None
    created_list = False
    try:
        for r in api.path("ip", "neighbor", "discovery-settings"):
            settings_id = r.get(".id")
            original = str(r.get("discover-interface-list"))
            break
        print(f"original discover-interface-list={original!r}")
        show_neighbours(api, "before")

        api.path("interface", "list").add(name=LIST_NAME)
        created_list = True
        for name in MEMBERS:
            api.path("interface", "list", "member").add(
                list=LIST_NAME, interface=name
            )
        api.path("ip", "neighbor", "discovery-settings").update(
            **{".id": settings_id, "discover-interface-list": LIST_NAME}
        )
        print(f"discovery pointed at {LIST_NAME} ({', '.join(MEMBERS)}) "
              f"for {WINDOW}s")

        time.sleep(WINDOW)
        show_neighbours(api, "after")

        found = [
            r for r in api.path("ip", "neighbor")
            if str(r.get("interface")) in ("ether2", "bridge")
        ]
        print()
        if found:
            print("VERDICT: the AP announces itself. Its management address and "
                  "model are in the rows above.")
        else:
            print("VERDICT: nothing announced on ether2 or the bridge in "
                  f"{WINDOW}s.")
            print("  The AP does not speak CDP/LLDP/MNDP toward this router, so")
            print("  the router cannot learn its address. Combined with no DHCP")
            print("  lease, no ARP entry, and nothing in 192.168.0.0/24 or")
            print("  192.168.2.0/24, there is no management address reachable")
            print("  from here to find. It has to come from the AP itself --")
            print("  its label, the Omada app, or a laptop connected to it.")
        return 0
    finally:
        try:
            if settings_id is not None and original is not None:
                api.path("ip", "neighbor", "discovery-settings").update(
                    **{".id": settings_id, "discover-interface-list": original}
                )
                print(f"\nrestored discover-interface-list={original!r}")
            for r in list(api.path("interface", "list", "member")):
                if str(r.get("list")) == LIST_NAME:
                    api.path("interface", "list", "member").remove(r[".id"])
            if created_list:
                for r in list(api.path("interface", "list")):
                    if str(r.get("name")) == LIST_NAME:
                        api.path("interface", "list").remove(r[".id"])
                        print(f"removed interface list {LIST_NAME}")
            leftover = [
                str(r.get("name")) for r in api.path("interface", "list")
                if str(r.get("name")) == LIST_NAME
            ]
            print("leftover temp list:", leftover if leftover else "none")
            for r in api.path("ip", "neighbor", "discovery-settings"):
                print("discovery now:", r.get("discover-interface-list"))
        except Exception as exc:  # noqa: BLE001
            print(f"\nCLEANUP FAILED: {exc}")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

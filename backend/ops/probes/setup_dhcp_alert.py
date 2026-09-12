"""Watch the guest-facing interfaces for a DHCP server that is not ours.

A consumer router in factory configuration was briefly on the guest bridge
announcing `192.168.1.1` (Atheros MAC, now gone). The address it claimed was
the small half of that: such a device usually serves DHCP too, and a rogue
DHCP server wins whenever it answers first -- guests get an address and a
gateway that go nowhere, and nothing on this router would have said so.

`/ip dhcp-server alert` watches an interface and logs when a DHCP reply comes
from a server outside `valid-server`. It only *logs*: it blocks nothing,
drops nothing, and cannot interrupt a working network. That is deliberate --
a guard that can itself break the guest network is not a guard.

`valid-server` is read off the device (the router's own MAC on that
interface), never typed in: a wrong MAC here would make every legitimate
reply look rogue and fill the log with false alarms.

One alert per interface that actually runs a DHCP server, because an
interface with no DHCP has nothing to compare against.

Default is a DRY RUN. Pass --apply to write.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
APPLY = "--apply" in sys.argv
TIMEOUT = "1h"


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
        serving = {
            str(r.get("interface"))
            for r in api.path("ip", "dhcp-server")
            if str(r.get("disabled")).lower() not in ("true", "yes")
        }
        macs = {
            str(r.get("name")): str(r.get("mac-address"))
            for r in api.path("interface")
            if r.get("mac-address")
        }
        existing = {
            str(r.get("interface")) for r in api.path("ip", "dhcp-server", "alert")
        }

        print(f"router={router['name']}")
        print(f"interfaces running DHCP: {sorted(serving)}")
        print(f"alerts already present:  {sorted(existing) or 'none'}\n")

        plan = []
        for iface in sorted(serving):
            if iface in existing:
                print(f"  {iface}: already watched -- skipping")
                continue
            mac = macs.get(iface)
            if not mac:
                print(f"  {iface}: no MAC readable for it -- skipping rather than "
                      "guessing a valid-server")
                continue
            plan.append((iface, mac))
            print(f"  {iface}: add alert, valid-server={mac}")

        stale = [
            r for r in api.path("ip", "dhcp-server", "alert")
            if str(r.get("comment")) == "cloudguest-rogue-dhcp-watch"
            and str(r.get("disabled")).lower() in ("true", "yes")
        ]
        for r in stale:
            print(f"  {r.get('interface')}: alert exists but is DISABLED "
                  "-- watching nothing")

        if not plan and not stale:
            print("\nnothing to do")
            return 0
        if not APPLY:
            print("\nDRY RUN -- nothing written. Re-run with --apply.")
            return 0

        # Disabled first: an alert that is present and off is the worst of
        # the two states, because the config looks like it is guarded.
        for r in stale:
            api.path("ip", "dhcp-server", "alert").update(
                **{".id": r[".id"], "disabled": "no"}
            )
            print(f"enabled alert on {r.get('interface')}")

        for iface, mac in plan:
            # RouterOS creates an alert row DISABLED unless told otherwise.
            # Adding one without this leaves a guard that is present and not
            # running -- visible in the config, watching nothing.
            api.path("ip", "dhcp-server", "alert").add(
                interface=iface,
                **{"valid-server": mac, "alert-timeout": TIMEOUT,
                   "disabled": "no"},
                comment="cloudguest-rogue-dhcp-watch",
            )
            print(f"added alert on {iface}")

        print("\n=== /ip dhcp-server alert now ===")
        for r in api.path("ip", "dhcp-server", "alert"):
            print(f"  interface={r.get('interface')!r} "
                  f"valid-server={r.get('valid-server')!r} "
                  f"alert-timeout={r.get('alert-timeout')!r} "
                  f"disabled={r.get('disabled')} "
                  f"comment={r.get('comment')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

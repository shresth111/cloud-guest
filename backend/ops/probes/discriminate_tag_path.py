"""Is the AP not tagging, or is the bridge swallowing the tag?

`vlan900` on the bridge received nothing while `ether2` received traffic.
That is consistent with two very different causes, and they need different
fixes:

  A. the access point is not emitting VLAN-900-tagged frames at all (or
     nothing is generating traffic on that SSID yet);
  B. it is, and a bridge with `vlan-filtering=no` does not hand tagged
     frames up to a VLAN interface layered on it -- in which case bridge
     VLAN filtering really is required.

This discriminates by creating a VLAN interface on the **physical port**
rather than on the bridge, and watching it. A sub-interface of `ether2` sees
what arrives on `ether2`.

  * it receives packets  -> the AP IS tagging (cause B)
  * it receives nothing  -> nothing tagged 900 is arriving (cause A)

Creates one interface with no address, no DHCP and no firewall rules, and
removes it again unless --keep is passed. Changes no bridge setting, so it
cannot disturb the live guest network.
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

_args = [a for a in sys.argv[1:] if not a.startswith("-")]
HOST = _args[0] if _args else "10.20.0.14"
KEEP = "--keep" in sys.argv
PORT = "ether2"
VID = "900"
PROBE_NAME = "cg-tagprobe-900"
GAP = 12


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


def rx_of(api, name: str) -> int:
    for r in api.path("interface"):
        if str(r.get("name")) == name:
            try:
                return int(r.get("rx-packet") or 0)
            except (TypeError, ValueError):
                return 0
    return -1


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
        timeout=25,
    )
    created = None
    try:
        existing = [
            r for r in api.path("interface", "vlan")
            if str(r.get("name")) == PROBE_NAME
        ]
        if existing:
            print(f"{PROBE_NAME} already present -- reusing it")
        else:
            created = api.path("interface", "vlan").add(
                name=PROBE_NAME,
                **{"vlan-id": VID},
                interface=PORT,
                comment="temporary tag-path probe, safe to delete",
            )
            print(f"created {PROBE_NAME} on {PORT} (vlan-id {VID})")

        print(f"watching for {GAP}s ...\n")
        before_probe = rx_of(api, PROBE_NAME)
        before_port = rx_of(api, PORT)
        before_vlan = rx_of(api, "vlan900")
        time.sleep(GAP)
        after_probe = rx_of(api, PROBE_NAME)
        after_port = rx_of(api, PORT)
        after_vlan = rx_of(api, "vlan900")

        print(f"{'interface':<18} {'rx-pkt':>10} {'delta':>8}")
        for label, a, b in [
            (f"{PROBE_NAME} (on {PORT})", before_probe, after_probe),
            ("vlan900 (on bridge)", before_vlan, after_vlan),
            (PORT, before_port, after_port),
        ]:
            print(f"{label:<18} {b:>10} {b - a:>8}")

        print()
        if after_probe - before_probe > 0:
            print("VERDICT: the AP IS tagging VLAN 900.")
            print("  A sub-interface of the physical port receives the frames, so")
            print("  the tag arrives on the wire and the BRIDGE is what does not")
            print("  pass it up to a VLAN interface with vlan-filtering=no.")
            print("  -> bridge VLAN filtering is genuinely required for the")
            print("     bridge-layered design, or the VLAN interface has to sit")
            print("     on the port instead.")
        elif after_port - before_port > 0:
            print("VERDICT: traffic is arriving on the port, but NONE of it is")
            print("  tagged 900. The access point is not emitting VLAN-900 frames")
            print("  on its uplink yet -- or no client has associated with that")
            print("  SSID, so the AP has nothing to send on it.")
            print("  -> nothing to conclude about the bridge. Connect a device to")
            print("     that SSID and re-run before changing any bridge setting.")
        else:
            print("VERDICT: the port itself received nothing in this window, so")
            print("  this run says nothing either way. Re-run while there is")
            print("  traffic.")
        return 0
    finally:
        if created is not None and not KEEP:
            try:
                for r in api.path("interface", "vlan"):
                    if str(r.get("name")) == PROBE_NAME:
                        api.path("interface", "vlan").remove(r[".id"])
                        print(f"\nremoved {PROBE_NAME}")
            except Exception as exc:  # noqa: BLE001
                print(f"\nCLEANUP FAILED for {PROBE_NAME}: {exc}")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

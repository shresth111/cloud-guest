"""Find the access point's IP without touching its configuration.

The AP on `ether2` has no DHCP lease and no ARP entry, so it holds a static
address outside every subnet the router currently carries -- which is why it
is invisible. TP-Link access points fall back to `192.168.0.254` when they
get no lease, so that subnet is the first place to look.

Method: add a TEMPORARY address on the bridge inside a candidate subnet,
ARP-sweep that subnet with `/tool ip-scan`, then remove the address again.
The sweep finds any host in the range, not only the guessed default.

`192.168.1.0/24` is deliberately NOT a candidate: `ether1` already carries
`192.168.1.100/24` toward the upstream router, and adding a second interface
in that subnet would create a routing ambiguity on a live WAN.

Every address this adds is removed in a `finally`, including on failure.
Nothing else is written -- no bridge setting, no DHCP, no firewall rule.

Default is a DRY RUN (prints the plan). Pass --apply to actually probe.
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

APPLY = "--apply" in sys.argv
HOST = "10.20.0.14"
BRIDGE = "bridge"
# (temporary address to add, range to sweep)
CANDIDATES = [
    ("192.168.0.9/24", "192.168.0.1-192.168.0.254"),
    ("192.168.2.9/24", "192.168.2.1-192.168.2.254"),
]
MARKER = "cg-ap-hunt-temp"


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
    if router is None:
        print(f"no router at {HOST}")
        return 2

    print("plan:")
    for addr, rng in CANDIDATES:
        print(f"  add {addr} on {BRIDGE}, ip-scan {rng}, remove it again")
    if not APPLY:
        print("\nDRY RUN -- nothing written. Re-run with --apply.")
        return 0

    api = librouteros.connect(
        host=HOST,
        username=router["api_username"],
        password=decrypt_secret(router["api_credentials_encrypted"]),
        port=8728,
        timeout=60,
    )
    added: list[str] = []
    try:
        for addr, rng in CANDIDATES:
            print(f"\n=== {addr} / sweep {rng} ===")
            try:
                new_id = api.path("ip", "address").add(
                    address=addr, interface=BRIDGE, comment=MARKER
                )
                added.append(new_id)
            except Exception as exc:  # noqa: BLE001
                print(f"  could not add the temporary address: {exc}")
                continue

            time.sleep(2)
            found = []
            try:
                for row in api("/tool/ip-scan", **{"address-range": rng,
                                                   "duration": "8"}):
                    ip = row.get("address")
                    mac = row.get("mac-address")
                    if ip or mac:
                        found.append((ip, mac, row.get("time")))
            except Exception as exc:  # noqa: BLE001
                print(f"  ip-scan unavailable ({type(exc).__name__}: {exc})")

            if found:
                for ip, mac, t in found:
                    print(f"  FOUND  ip={ip!r} mac={mac!r} rtt={t!r}")
            else:
                print("  nothing answered in this subnet")

            print("  --- ARP learned during the sweep ---")
            for r in api.path("ip", "arp"):
                if str(r.get("interface")) in (BRIDGE, "ether2"):
                    print(f"    {r.get('address')!r} mac={r.get('mac-address')!r} "
                          f"if={r.get('interface')!r}")
        return 0
    finally:
        # Remove every address this run added, by the marker it stamped --
        # never by index, and never anything it did not create.
        for row in list(api.path("ip", "address")):
            if str(row.get("comment")) == MARKER:
                try:
                    api.path("ip", "address").remove(row[".id"])
                    print(f"\nremoved temporary {row.get('address')}")
                except Exception as exc:  # noqa: BLE001
                    print(f"\nCLEANUP FAILED for {row.get('address')}: {exc}")
        left = [
            str(r.get("address")) for r in api.path("ip", "address")
            if str(r.get("comment")) == MARKER
        ]
        print("temporary addresses left:", left if left else "none")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

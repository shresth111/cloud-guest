"""Read-only: does a tagged frame actually reach a VLAN interface?

This is the test that decides the tagged-to-AP architecture. With
`vlan-filtering=no` the bridge ignores VLAN tags for forwarding purposes --
what MikroTik's docs do NOT say is whether a `/interface vlan` layered on
that bridge still receives frames carrying its VID. If it does, no bridge
change is needed at all.

Reads the interface counters twice, a few seconds apart, and reports the
delta. A single snapshot cannot distinguish "traffic is arriving" from
"something arrived once, long ago" -- the delta can.

Writes nothing.
"""

import asyncio
import sys
import time

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"
WATCH = sys.argv[2] if len(sys.argv) > 2 else "vlan900"
GAP = 8


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


def counters(api) -> dict:
    out = {}
    for r in api.path("interface"):
        name = str(r.get("name"))
        out[name] = {
            "rx-packet": r.get("rx-packet"),
            "tx-packet": r.get("tx-packet"),
            "rx-byte": r.get("rx-byte"),
            "running": r.get("running"),
        }
    return out


def as_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


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
        timeout=20,
    )
    try:
        first = counters(api)
        if WATCH not in first:
            print(f"no interface named {WATCH!r} on this device")
            print("interfaces:", sorted(first))
            return 1
        print(f"router={router['name']}  watching {WATCH!r} for {GAP}s\n")
        time.sleep(GAP)
        second = counters(api)

        print(f"{'interface':<16} {'rx-pkt':>12} {'Δrx-pkt':>9} "
              f"{'rx-byte':>14} {'Δrx-byte':>10}  running")
        for name in sorted(second):
            if name not in (WATCH, "bridge", "ether2", "ether1"):
                continue
            a, b = first.get(name, {}), second[name]
            d_pkt = as_int(b["rx-packet"]) - as_int(a.get("rx-packet"))
            d_byte = as_int(b["rx-byte"]) - as_int(a.get("rx-byte"))
            print(f"{name:<16} {as_int(b['rx-packet']):>12} {d_pkt:>9} "
                  f"{as_int(b['rx-byte']):>14} {d_byte:>10}  {b['running']}")

        w = second[WATCH]
        total = as_int(w["rx-packet"])
        delta = total - as_int(first[WATCH].get("rx-packet"))
        print()
        if delta > 0:
            print(f"VERDICT: {WATCH} is RECEIVING tagged frames "
                  f"(+{delta} packets in {GAP}s).")
            print("  A VLAN interface on a bridge with vlan-filtering=no does get")
            print("  frames carrying its VID. No bridge change is needed.")
        elif total > 0:
            print(f"VERDICT: {WATCH} has {total} packets total but none in the last "
                  f"{GAP}s.")
            print("  Something reached it at some point. Re-run while the AP is")
            print("  actually passing traffic on that SSID before concluding.")
        else:
            print(f"VERDICT: {WATCH} has received NOTHING (rx-packet=0).")
            print("  Either the AP is not tagging 900 on its uplink yet, or the")
            print("  bridge does not pass tagged frames up to the VLAN interface")
            print("  with vlan-filtering=no -- and then bridge VLAN filtering is")
            print("  required. Check the AP's VLAN setting before assuming the")
            print("  second: a silent AP and a filtering bridge look identical here.")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

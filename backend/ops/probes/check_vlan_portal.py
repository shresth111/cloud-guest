"""Is a VLAN's captive portal actually able to let someone in?

A portal that exists is not a portal that works. This reports, for one VLAN
interface: its hotspot server and profile, whether the profile points at
RADIUS, the DNS name it redirects to, and who is currently associated and
whether they are authorised.

`authorized=False` on a host is normal before login and is what makes the
portal appear; it is only a problem if it never becomes True after someone
signs in.

Writes nothing.

  check_vlan_portal.py [vlan-interface]
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

HOST = "10.20.0.14"
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
VLAN_IF = _args[0] if _args else "vlan95"


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
        servers = [
            r for r in api.path("ip", "hotspot")
            if str(r.get("interface")) == VLAN_IF
        ]
        print(f"=== /ip hotspot on {VLAN_IF} ===")
        if not servers:
            print("  NONE -- this VLAN has no portal")
            return 0
        profile_names = set()
        for r in servers:
            profile_names.add(str(r.get("profile")))
            print(f"  name={r.get('name')!r} profile={r.get('profile')!r} "
                  f"disabled={r.get('disabled')} invalid={r.get('invalid')}")

        print("\n=== its profile ===")
        for r in api.path("ip", "hotspot", "profile"):
            if str(r.get("name")) in profile_names:
                print(f"  name={r.get('name')!r} "
                      f"hotspot-address={r.get('hotspot-address')!r} "
                      f"dns-name={r.get('dns-name')!r} "
                      f"use-radius={r.get('use-radius')} "
                      f"login-by={r.get('login-by')!r} "
                      f"html-directory={r.get('html-directory')!r}")

        print("\n=== /ip hotspot host (who is on it) ===")
        hosts = [
            r for r in api.path("ip", "hotspot", "host")
            if str(r.get("server")) in {str(s.get("name")) for s in servers}
        ]
        if not hosts:
            print("  (nobody associated right now)")
        for r in hosts:
            print(f"  {r.get('address')!r} mac={r.get('mac-address')!r} "
                  f"authorized={r.get('authorized')} bypassed={r.get('bypassed')}")

        print("\n=== /ip hotspot active (logged in) ===")
        active = [
            r for r in api.path("ip", "hotspot", "active")
            if str(r.get("server")) in {str(s.get("name")) for s in servers}
        ]
        if not active:
            print("  (nobody logged in yet)")
        for r in active:
            print(f"  {r.get('address')!r} user={r.get('user')!r} "
                  f"uptime={r.get('uptime')!r}")

        print("\n=== walled garden (reachable before login) ===")
        wg = list(api.path("ip", "hotspot", "walled-garden"))
        if not wg:
            print("  (empty -- nothing is reachable before login)")
        for r in wg[:12]:
            print(f"  dst-host={r.get('dst-host')!r} action={r.get('action')!r} "
                  f"comment={r.get('comment')!r}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())

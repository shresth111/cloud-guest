"""Re-Apply one VLAN through the real endpoint, and show the profile before
and after.

A configuration fix does not reach a router by being deployed -- it reaches
it on the next push. This re-pushes one VLAN so its hotspot profile
converges, and prints `use-radius`/`login-by` either side so the change is
visible rather than assumed.

  reapply_vlan.py <vlan-interface>     e.g. vlan95
"""

import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

HOST = "10.20.0.14"
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
VLAN_IF = _args[0] if _args else "vlan95"


class _PermitAll:
    async def check(self, *args, **kwargs) -> None:
        return None


def profiles(router_row, label):
    import librouteros

    from app.domains.router.crypto import decrypt_secret

    api = librouteros.connect(
        host=HOST,
        username=router_row["api_username"],
        password=decrypt_secret(router_row["api_credentials_encrypted"]),
        port=8728,
        timeout=25,
    )
    try:
        print(f"\n--- /ip hotspot profile ({label}) ---")
        for r in api.path("ip", "hotspot", "profile"):
            print(f"  {str(r.get('name')):<16} use-radius={r.get('use-radius')!s:<6} "
                  f"login-by={r.get('login-by')!r}")
    finally:
        api.close()


async def main() -> int:
    import asyncpg
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.common.exceptions import register_exception_handlers
    from app.core.config import get_settings
    from app.domains.auth.models import AuthUser
    from app.domains.rbac.dependencies import (
        CurrentOrganization,
        get_access_validator,
        get_current_user,
    )
    from app.domains.vlan.router import router as vlan_router

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router_row = await conn.fetchrow(
            "SELECT id, name, organization_id, api_username, "
            "api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            HOST,
        )
        vlan = await conn.fetchrow(
            "SELECT id, name, vlan_id, enable_hotspot FROM vlans "
            "WHERE router_id = $1 AND is_deleted = false "
            "AND mikrotik_interface_name = $2 LIMIT 1",
            router_row["id"],
            VLAN_IF,
        )
    finally:
        await conn.close()

    if vlan is None:
        print(f"no VLAN whose device interface is {VLAN_IF!r}")
        return 2
    print(f"router={router_row['name']}  vlan={vlan['name']!r} "
          f"id={vlan['vlan_id']} portal={vlan['enable_hotspot']}")

    profiles(router_row, "before")

    actor = AuthUser(id=str(uuid.uuid4()), email="probe@wyfyguest.com")
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(vlan_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: router_row[
        "organization_id"
    ]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://probe") as client:
        resp = await client.post(f"/api/v1/vlans/{vlan['id']}/push")
        print(f"\nPOST /vlans/{{id}}/push -> {resp.status_code}")
        if resp.status_code >= 300:
            print(resp.text[:600])

    profiles(router_row, "after")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

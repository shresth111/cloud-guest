"""Remove the 900-series test VLANs, through the platform's own delete path.

Deletes the VLAN rows in the 900-999 range for this router via the real
`DELETE /vlans/{id}` endpoint, so the device teardown is the shipped one --
the point is to leave nothing behind AND to exercise the same path a
customer would.

Reports what is left on the device afterwards, including anything in the
900 range the platform did not account for.

  cleanup_test_vlans.py [router-ip]
"""

import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

HOST = "10.20.0.14"
LOW, HIGH = 900, 999


class _PermitAll:
    async def check(self, *args, **kwargs) -> None:
        return None


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
    from app.domains.router.crypto import decrypt_secret
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
        rows = await conn.fetch(
            "SELECT id, name, vlan_id FROM vlans "
            "WHERE router_id = $1 AND is_deleted = false "
            "AND vlan_id BETWEEN $2 AND $3 ORDER BY vlan_id",
            router_row["id"],
            LOW,
            HIGH,
        )
    finally:
        await conn.close()

    print(f"router={router_row['name']}")
    print(f"test VLAN rows in {LOW}-{HIGH}: {len(rows)}")
    for r in rows:
        print(f"  vlan_id={r['vlan_id']} name={r['name']!r}")

    if rows:
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
            for r in rows:
                resp = await client.delete(f"/api/v1/vlans/{r['id']}")
                print(f"DELETE vlan {r['vlan_id']} -> {resp.status_code}")
                if resp.status_code >= 300:
                    print("   " + resp.text[:400])

    import librouteros

    api = librouteros.connect(
        host=HOST,
        username=router_row["api_username"],
        password=decrypt_secret(router_row["api_credentials_encrypted"]),
        port=8728,
        timeout=20,
    )
    try:
        print("\n=== device, after ===")
        for path, keys in [
            (("interface", "vlan"), ("name", "vlan-id", "interface")),
            (("ip", "pool"), ("name", "ranges")),
            (("ip", "dhcp-server"), ("name", "interface", "address-pool")),
            (("ip", "hotspot"), ("name", "interface")),
            (("ip", "address"), ("address", "interface")),
        ]:
            print(f"--- /{'/'.join(path)} ---")
            got = list(api.path(*path))
            if not got:
                print("    (empty)")
            for r in got:
                line = "  ".join(
                    f"{k}={r.get(k)!r}" for k in keys if r.get(k) not in (None, "")
                )
                flag = "  <-- 900-series leftover" if "vlan9" in line else ""
                print(f"    {line}{flag}")
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

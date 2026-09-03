"""Prove, on real hardware, what a trunk VLAN with the portal ON creates.

The claim under test is one I have been making in words: `port_mode="trunk"`
plus `enable_hotspot=True` creates the VLAN interface AND its IP pool, DHCP
server, network row, hotspot profile and hotspot server -- i.e. the customer
does not have to create a pool by hand, and no physical port is consumed.

Runs the real shipped path: mounts the actual `vlan` router and calls
`POST /vlans` then `POST /vlans/{id}/push` in-process, so FastAPI resolves
the real dependency chain. Only auth and the permission check are stubbed.

Uses VLAN id 900 -- the range reserved for test scaffolding on this fleet --
on parent `bridge`, with NAT off. Additive only; the bridge has
`vlan-filtering=False`, so a tagged sub-interface carries no traffic and
cannot disturb the live guest network.

Cleans up after itself unless --keep is passed.
"""

import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

KEEP = "--keep" in sys.argv
HOST = "10.20.0.14"
VLAN_ID = 900
CIDR = "10.90.0.0/24"
GATEWAY = "10.90.0.1"


class _PermitAll:
    async def check(self, *args, **kwargs) -> None:
        return None


def device_state(router_row, label):
    import librouteros

    from app.domains.router.crypto import decrypt_secret

    api = librouteros.connect(
        host=HOST,
        username=router_row["api_username"],
        password=decrypt_secret(router_row["api_credentials_encrypted"]),
        port=8728,
        timeout=15,
    )
    try:
        print(f"\n########## {label} ##########")
        for path, keys in [
            (("interface", "vlan"), ("name", "vlan-id", "interface", "comment")),
            (("ip", "address"), ("address", "interface")),
            (("ip", "pool"), ("name", "ranges")),
            (("ip", "dhcp-server"), ("name", "interface", "address-pool", "disabled")),
            (("ip", "dhcp-server", "network"), ("address", "gateway", "dns-server")),
            (("ip", "hotspot"), ("name", "interface", "profile", "disabled")),
        ]:
            print(f"--- /{'/'.join(path)} ---")
            rows = list(api.path(*path))
            if not rows:
                print("    (empty)")
            for r in rows:
                print("    " + "  ".join(
                    f"{k}={r.get(k)!r}" for k in keys if r.get(k) not in (None, "")
                ))
    finally:
        api.close()


async def main() -> int:
    import asyncpg
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select

    from app.common.exceptions import register_exception_handlers
    from app.core.config import get_settings
    from app.database.session import SessionLocal
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
            "SELECT id, name, organization_id, location_id, api_username, "
            "api_credentials_encrypted FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            HOST,
        )
    finally:
        await conn.close()
    if router_row is None:
        print(f"no router at {HOST}")
        return 2
    print(f"router={router_row['name']} id={router_row['id']}")

    device_state(router_row, "BEFORE")

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
        create = await client.post(
            "/api/v1/vlans",
            json={
                "router_id": str(router_row["id"]),
                "name": "QA trunk portal 900",
                "vlan_id": VLAN_ID,
                "interface": "bridge",
                "cidr": CIDR,
                "gateway_ip_address": GATEWAY,
                "port_mode": "trunk",
                "enable_hotspot": True,
                "nat_enabled": False,
                "is_enabled": True,
            },
        )
        print(f"\nPOST /vlans -> {create.status_code}")
        if create.status_code >= 300:
            print(create.text[:900])
            return 1
        vlan_id = create.json()["data"]["id"]
        print(f"vlan row id={vlan_id}")

        push = await client.post(f"/api/v1/vlans/{vlan_id}/push")
        print(f"POST /vlans/{{id}}/push -> {push.status_code}")
        body = push.json().get("data", {}) if push.status_code < 300 else {}
        if push.status_code >= 300:
            print(push.text[:900])
        else:
            status = body.get("devicePushStatus") or body.get("device_push_status")
            error = body.get("devicePushError") or body.get("device_push_error")
            print(f"device_push_status={status!r}")
            print(f"device_push_error={error!r}")

        device_state(router_row, "AFTER PUSH")

        if KEEP:
            print("\n--keep: leaving the VLAN in place")
            return 0

        delete = await client.delete(f"/api/v1/vlans/{vlan_id}")
        print(f"\nDELETE /vlans/{{id}} -> {delete.status_code}")
        if delete.status_code >= 300:
            print(delete.text[:900])

    device_state(router_row, "AFTER DELETE")

    async with SessionLocal() as session:
        from app.domains.vlan.models import Vlan

        left = (
            await session.execute(
                select(Vlan).where(
                    Vlan.router_id == router_row["id"],
                    Vlan.is_deleted.is_(False),
                )
            )
        ).scalars().all()
        print(f"\nVLAN rows left for this router: {len(left)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

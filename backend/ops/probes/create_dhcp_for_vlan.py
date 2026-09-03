"""Give a portal-less VLAN the DHCP server it is missing.

A VLAN created with `enable_hotspot=false` gets an interface and an address
and nothing else -- no pool, no DHCP server -- so a client on it never gets
an address and nothing works. The product's own answer is to create a DHCP
pool on the IP Addresses page pointing at that VLAN's interface; this does
exactly that, through the real `POST /dhcp-pools` and `POST
/dhcp-pools/{id}/push`, so what runs is the shipped path.

Derives the range and gateway from the VLAN's own CIDR rather than taking
them as arguments -- the two must agree, and asking for them again is asking
to get them wrong.

  create_dhcp_for_vlan.py <vlan-interface>   e.g. vlan12
"""

import asyncio
import ipaddress
import sys
import uuid

sys.path.insert(0, "/app")

HOST = "10.20.0.14"
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
VLAN_IF = _args[0] if _args else "vlan12"


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
    from app.domains.dhcp.router import router as dhcp_router
    from app.domains.rbac.dependencies import (
        CurrentOrganization,
        get_access_validator,
        get_current_user,
    )

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        router_row = await conn.fetchrow(
            "SELECT id, name, organization_id FROM routers "
            "WHERE management_ip_address = $1 LIMIT 1",
            HOST,
        )
        vlan = await conn.fetchrow(
            "SELECT name, vlan_id, cidr, gateway_ip_address, enable_hotspot "
            "FROM vlans WHERE router_id = $1 AND is_deleted = false "
            "AND mikrotik_interface_name = $2 LIMIT 1",
            router_row["id"],
            VLAN_IF,
        )
    finally:
        await conn.close()

    if vlan is None:
        print(f"no VLAN row whose device interface is {VLAN_IF!r}")
        return 2
    if vlan["enable_hotspot"]:
        print(f"{VLAN_IF} has the captive portal ON -- it already has a pool and a")
        print("DHCP server from that. Nothing to add.")
        return 0

    net = ipaddress.ip_network(vlan["cidr"], strict=False)
    gateway = vlan["gateway_ip_address"] or str(next(net.hosts()))
    hosts = list(net.hosts())
    start = str(hosts[9]) if len(hosts) > 20 else str(hosts[1])
    end = str(hosts[-2])

    print(f"router={router_row['name']}  vlan={vlan['name']!r} "
          f"id={vlan['vlan_id']} cidr={vlan['cidr']}")
    print(f"pool: {start} - {end}   gateway/dns: {gateway}   interface: {VLAN_IF}")

    actor = AuthUser(id=str(uuid.uuid4()), email="probe@wyfyguest.com")
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(dhcp_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: router_row[
        "organization_id"
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://probe") as client:
        create = await client.post(
            "/api/v1/dhcp-pools",
            json={
                "router_id": str(router_row["id"]),
                "name": f"{vlan['name']} pool",
                "address_range_start": start,
                "address_range_end": end,
                "interface": VLAN_IF,
                "gateway_ip_address": gateway,
                "dns_primary": gateway,
                "is_enabled": True,
            },
        )
        print(f"\nPOST /dhcp-pools -> {create.status_code}")
        if create.status_code >= 300:
            print(create.text[:800])
            return 1
        pool_id = create.json()["data"]["id"]

        push = await client.post(f"/api/v1/dhcp-pools/{pool_id}/push")
        print(f"POST /dhcp-pools/{{id}}/push -> {push.status_code}")
        if push.status_code >= 300:
            print(push.text[:800])
            return 1
        data = push.json().get("data", {})
        print("device_push_status="
              f"{data.get('devicePushStatus') or data.get('device_push_status')!r}")
        print("device_push_error="
              f"{data.get('devicePushError') or data.get('device_push_error')!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

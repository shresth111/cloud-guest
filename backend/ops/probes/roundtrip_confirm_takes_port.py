"""End-to-end: refuse without consent, accept with it, give the port back.

Exercises three changes at once, through the real endpoints:

  * cloud-guest#130  -- an access-mode push onto a bridge member is refused
    (409) unless `confirm_takes_port` is set
  * foundation#196   -- the field the dashboard now sends
  * cloud-guest#126  -- `previous_bridge`, so delete returns the port to the
    bridge it was taken from

Uses `ether5`: idle on this router, nothing plugged in, so even a failure
mid-run costs nothing. VLAN id 902 is in the range reserved for scaffolding.

Every step asserts the DEVICE, not the API's opinion of it. Cleans up in a
`finally` and prints the bridge membership before and after so the two can
be compared rather than trusted.
"""

import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

HOST = "10.20.0.14"
PORT = "ether5"
VLAN_ID = 902
CIDR = "10.92.0.0/24"
GATEWAY = "10.92.0.1"


class _PermitAll:
    async def check(self, *args, **kwargs) -> None:
        return None


def bridge_members(router_row):
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
        members = {
            str(r.get("interface")): str(r.get("bridge"))
            for r in api.path("interface", "bridge", "port")
        }
        addrs = [
            str(r.get("address"))
            for r in api.path("ip", "address")
            if str(r.get("interface")) == PORT
        ]
        return members, addrs
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
    finally:
        await conn.close()

    before, before_addrs = bridge_members(router_row)
    print(f"router={router_row['name']}")
    print(f"BEFORE  bridge members: {sorted(before)}")
    print(f"        {PORT} bridge={before.get(PORT)!r} addresses={before_addrs}")
    if PORT not in before:
        print(f"\n{PORT} is not in a bridge -- this test needs it to be. Stopping.")
        return 2

    actor = AuthUser(id=str(uuid.uuid4()), email="probe@wyfyguest.com")
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(vlan_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: router_row[
        "organization_id"
    ]

    vlan_id = None
    failures = []
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://probe") as c:
            create = await c.post(
                "/api/v1/vlans",
                json={
                    "router_id": str(router_row["id"]),
                    "name": "QA consent 902",
                    "vlan_id": VLAN_ID,
                    "interface": PORT,
                    "cidr": CIDR,
                    "gateway_ip_address": GATEWAY,
                    "port_mode": "access",
                    "enable_hotspot": False,
                    "nat_enabled": False,
                    "is_enabled": True,
                    "confirm_takes_port": False,
                },
            )
            print(f"\n1. create (confirm=false) -> {create.status_code}")
            if create.status_code >= 300:
                print(create.text[:500])
                return 1
            vlan_id = create.json()["data"]["id"]

            push = await c.post(f"/api/v1/vlans/{vlan_id}/push")
            print(f"2. push WITHOUT consent   -> {push.status_code}")
            body = push.text
            print(f"   {body[:260]}")
            if push.status_code != 409:
                failures.append(f"expected 409 without consent, got {push.status_code}")
            for token in (PORT, "bridge"):
                if token not in body:
                    failures.append(f"refusal does not name {token!r}")

            mid, mid_addrs = bridge_members(router_row)
            still_in = mid.get(PORT)
            print(f"3. {PORT} after refusal    -> bridge={still_in!r} "
                  f"addresses={mid_addrs}")
            if still_in != before.get(PORT):
                failures.append("a refused push moved the port anyway")
            if mid_addrs:
                failures.append("a refused push put an address on the port")

            upd = await c.put(
                f"/api/v1/vlans/{vlan_id}", json={"confirm_takes_port": True}
            )
            print(f"4. update (confirm=true)  -> {upd.status_code}")

            push2 = await c.post(f"/api/v1/vlans/{vlan_id}/push")
            print(f"5. push WITH consent      -> {push2.status_code}")
            if push2.status_code != 200:
                print(f"   {push2.text[:400]}")
                failures.append(f"consented push failed with {push2.status_code}")

            taken, taken_addrs = bridge_members(router_row)
            print(
                f"6. {PORT} after push       -> "
                f"bridge={taken.get(PORT)!r} addresses={taken_addrs}"
            )
            if PORT in taken:
                failures.append("consented push did not take the port from the bridge")
            if not taken_addrs:
                failures.append("consented push left no address on the port")

            delete = await c.delete(f"/api/v1/vlans/{vlan_id}")
            print(f"7. delete                 -> {delete.status_code}")
            vlan_id = None

        after, after_addrs = bridge_members(router_row)
        print(f"\nAFTER   bridge members: {sorted(after)}")
        print(f"        {PORT} bridge={after.get(PORT)!r} addresses={after_addrs}")
        if after.get(PORT) != before.get(PORT):
            failures.append("delete did not return the port to its bridge")
        if after_addrs != before_addrs:
            failures.append("delete left an address behind")
        if sorted(after) != sorted(before):
            failures.append("bridge membership differs from the start")

        print()
        if failures:
            for f in failures:
                print(f"FAIL: {f}")
            return 1
        print("ROUND TRIP PASSED: refused without consent, applied with it, "
              "port returned on delete")
        return 0
    finally:
        if vlan_id:
            print(f"\ncleanup: deleting leftover vlan {vlan_id}")
            async with AsyncClient(transport=transport, base_url="http://probe") as c:
                r = await c.delete(f"/api/v1/vlans/{vlan_id}")
                print(f"  -> {r.status_code}")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

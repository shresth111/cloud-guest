"""Run the REAL push against the lab router, through the shipped endpoint.

Not a reimplementation. This mounts the actual ``nas_router`` and calls
``POST /radius/nas/{id}/push`` in-process, so FastAPI resolves the real
dependency chain and the request goes through the real
``RadiusService.push_nas_client_to_device``, the real adapter, and the real
gateway writer. Only authentication and the permission check are stubbed --
this runs as an operator would, without needing a token.

The dry run (``dryrun_radius_push.py``) established what this changes on
the lab router: the ``/radius`` row already holds the right server address,
the right ``src-address``, and the same secret as the database, so the only
real change is ``/radius incoming accept`` false -> yes, plus stamping the
platform's own comment on a row somebody wrote by hand.
"""

import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"


class _PermitAll:
    async def check(self, *args, **kwargs) -> None:
        return None


async def main() -> int:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select

    from app.common.exceptions import register_exception_handlers
    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser
    from app.domains.guest.models import RadiusNasClient
    from app.domains.guest.router import nas_router
    from app.domains.rbac.dependencies import (
        CurrentOrganization,
        get_access_validator,
        get_current_user,
    )
    from app.domains.router.models import Router

    async with SessionLocal() as session:
        router = (
            await session.execute(
                select(Router).where(Router.management_ip_address == TARGET_HOST)
            )
        ).scalar_one_or_none()
        if router is None:
            print(f"no router at {TARGET_HOST}")
            return 2
        nas = (
            await session.execute(
                select(RadiusNasClient).where(
                    RadiusNasClient.router_id == router.id,
                    RadiusNasClient.is_deleted.is_(False),
                    RadiusNasClient.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if nas is None:
            print("no active NAS row for this router")
            return 2
        print(f"router={router.name} host={TARGET_HOST}")
        print(f"nas_id={nas.id}")
        print(f"before: device_push_status={nas.device_push_status} "
              f"device_pushed_at={nas.device_pushed_at}")
        nas_id = nas.id

    actor = AuthUser(id=str(uuid.uuid4()), email="probe@wyfyguest.com")

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(nas_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://probe") as client:
        resp = await client.post(f"/api/v1/radius/nas/{nas_id}/push")
    print(f"\nHTTP {resp.status_code}")
    print(resp.text[:1200])

    async with SessionLocal() as session:
        nas = (
            await session.execute(
                select(RadiusNasClient).where(RadiusNasClient.id == nas_id)
            )
        ).scalar_one()
        print(f"\nafter:  device_push_status={nas.device_push_status}")
        print(f"        device_pushed_at={nas.device_pushed_at}")
        print(f"        device_push_error={nas.device_push_error}")
    return 0 if resp.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

"""``GET /routers/{id}/device-connection`` and ``POST /routers/{id}/webfig-session``
must be operator-only.

Both hand out a full admin login on the device: the first returns the
platform's decrypted RouterOS API credentials, the second opens WebFig. They
used to call ``RequirePermission("routers.manage")`` with no ``scope=``, so the
check ran at whatever scope the caller sent. ``organization-owner`` holds
``routers.manage`` at organization scope (its default level is FULL), so any
venue owner's token could read the credentials for its own routers.

These tests take the dependency off the real route object, so a future edit
that drops the ``scope=`` fails here rather than in a pentest.
"""

from __future__ import annotations

import uuid

import pytest
from starlette.requests import Request

from app.domains.rbac import dependencies as rbac_dependencies
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError

from .test_rbac import FakeRBACRepository, assign_role, make_permission, make_role

ROUTES = (
    ("GET", "/routers/{router_id}/device-connection"),
    ("POST", "/routers/{router_id}/webfig-session"),
)


class _FakeUser:
    def __init__(self, user_id: uuid.UUID) -> None:
        self.id = str(user_id)


def _permission_dependency(method: str, path: str):
    from app.domains.router.router import router as api_router

    route = next(
        r
        for r in api_router.routes
        if getattr(r, "path", None) == path and method in getattr(r, "methods", ())
    )
    (dependency,) = [d.dependency for d in route.dependencies]
    return dependency


def _request(org_id: uuid.UUID, router_id: uuid.UUID) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": f"/api/v1/routers/{router_id}/device-connection",
            "headers": [(b"x-organization-id", str(org_id).encode())],
            "path_params": {"router_id": str(router_id)},
        }
    )


async def _validator_with(scope_type: ScopeType, org_id: uuid.UUID | None):
    repo = FakeRBACRepository()
    permission = await make_permission(repo, "routers", "manage")
    role = await make_role(repo, f"role-{scope_type.value}", scope_type=scope_type)
    await repo.add_role_permission(role.id, permission.id, granted_by=None)
    user_id = uuid.uuid4()
    await assign_role(
        repo,
        user_id=user_id,
        role=role,
        scope_type=scope_type,
        organization_id=org_id,
    )
    return AccessValidator(repo), _FakeUser(user_id)


@pytest.fixture
def scope_context(monkeypatch):
    """The router-in-org containment lookup needs a DB; pin the context it
    would produce: the caller's own org, and a router inside it."""
    org_id = uuid.uuid4()
    router_id = uuid.uuid4()

    async def _fake_context(request, db):
        return ScopeContext(organization_id=org_id, router_id=router_id)

    monkeypatch.setattr(rbac_dependencies, "_current_scope_context", _fake_context)
    return org_id, router_id


@pytest.mark.parametrize(("method", "path"), ROUTES)
async def test_organization_owner_is_refused_with_403(scope_context, method, path):
    org_id, router_id = scope_context
    validator, user = await _validator_with(ScopeType.ORGANIZATION, org_id)
    dependency = _permission_dependency(method, path)

    with pytest.raises(PermissionDeniedError) as excinfo:
        await dependency(
            _request(org_id, router_id), user=user, access_validator=validator, db=None
        )
    assert excinfo.value.status_code == 403


@pytest.mark.parametrize(("method", "path"), ROUTES)
async def test_global_operator_is_allowed(scope_context, method, path):
    org_id, router_id = scope_context
    validator, user = await _validator_with(ScopeType.GLOBAL, None)
    dependency = _permission_dependency(method, path)

    result = await dependency(
        _request(org_id, router_id), user=user, access_validator=validator, db=None
    )
    assert result is user

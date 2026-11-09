"""Who may ``POST /organizations`` (security review 2026-11-06, C1, with the
owner's MSP decision): platform staff anything; an MSP organization's own
staff only a child of THEIR MSP; a plain tenant owner nobody."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.organization.router import authorize_organization_create
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError

MSP_ORG = uuid.uuid4()
TENANT_ORG = uuid.uuid4()
OTHER_MSP = uuid.uuid4()
ACTOR = uuid.uuid4()


class FakeAccess:
    """Grants ``organizations.create`` at GLOBAL scope or in given orgs."""

    def __init__(self, *, global_grant: bool = False, org_grants=()) -> None:
        self.global_grant = global_grant
        self.org_grants = set(org_grants)

    async def has_permission(self, user_id, key, *, scope_type, scope_context):
        assert key == "organizations.create"
        if scope_type == ScopeType.GLOBAL:
            return self.global_grant
        return scope_context.organization_id in self.org_grants


class FakeOrganizations:
    def __init__(self) -> None:
        self.rows = {
            MSP_ORG: SimpleNamespace(is_msp=lambda: True),
            OTHER_MSP: SimpleNamespace(is_msp=lambda: True),
            TENANT_ORG: SimpleNamespace(is_msp=lambda: False),
        }

    async def get_organization(self, organization_id):
        return self.rows[organization_id]


async def _authorize(*, access, parent, header):
    return await authorize_organization_create(
        actor_user_id=ACTOR,
        requested_parent_id=parent,
        requesting_organization_id=header,
        access_validator=access,
        organization_service=FakeOrganizations(),
    )


async def test_msp_owner_creates_a_child_of_their_own_msp() -> None:
    access = FakeAccess(org_grants={MSP_ORG})
    assert await _authorize(access=access, parent=MSP_ORG, header=MSP_ORG) == MSP_ORG


async def test_the_dashboard_wizard_sends_no_parent_and_gets_the_callers_msp() -> None:
    """OrganizationWizard posts no parent_organization_id; the new org is
    linked under the caller's MSP rather than created top-level."""
    access = FakeAccess(org_grants={MSP_ORG})
    assert await _authorize(access=access, parent=None, header=MSP_ORG) == MSP_ORG


async def test_msp_owner_naming_another_org_as_parent_is_403() -> None:
    access = FakeAccess(org_grants={MSP_ORG})
    with pytest.raises(PermissionDeniedError) as exc:
        await _authorize(access=access, parent=OTHER_MSP, header=MSP_ORG)
    assert exc.value.status_code == 403


async def test_msp_staff_without_the_grant_in_their_msp_is_403() -> None:
    access = FakeAccess(org_grants={OTHER_MSP})
    with pytest.raises(PermissionDeniedError):
        await _authorize(access=access, parent=None, header=MSP_ORG)


async def test_a_plain_tenant_owner_is_403() -> None:
    access = FakeAccess(org_grants={TENANT_ORG})
    with pytest.raises(PermissionDeniedError) as exc:
        await _authorize(access=access, parent=None, header=TENANT_ORG)
    assert exc.value.status_code == 403
    with pytest.raises(PermissionDeniedError):
        await _authorize(access=access, parent=TENANT_ORG, header=TENANT_ORG)


async def test_no_organization_context_is_403() -> None:
    with pytest.raises(PermissionDeniedError):
        await _authorize(access=FakeAccess(), parent=None, header=None)


async def test_platform_staff_create_anything_as_requested() -> None:
    access = FakeAccess(global_grant=True)
    assert await _authorize(access=access, parent=None, header=None) is None
    assert (
        await _authorize(access=access, parent=OTHER_MSP, header=MSP_ORG) == OTHER_MSP
    )


def test_the_route_runs_the_authorization() -> None:
    from fastapi.routing import APIRoute

    from app.main import app

    [route] = [
        r
        for r in app.routes
        if isinstance(r, APIRoute)
        and r.path == "/api/v1/organizations"
        and "POST" in r.methods
    ]
    names = {d.name for d in route.dependant.dependencies}
    assert {"requesting_organization_id", "access_validator"} <= names

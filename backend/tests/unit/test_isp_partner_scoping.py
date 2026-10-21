"""IspScope and RequireIspPartner: every cross-ISP, cross-confinement and
wrong-shape id is the same 404; GLOBAL callers and non-ISP roles are 403."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import dependencies as deps
from app.domains.isp_partner.exceptions import (
    IspCustomerNotFoundError,
    IspLocationNotFoundError,
    IspPartnerRequiredError,
    IspPartnerSuspendedError,
    IspPortalConfigNotFoundError,
    IspRoleRequiredError,
    IspRouterNotFoundError,
    IspScopeHeadersNotAllowedError,
)
from app.domains.isp_partner.scoping import IspScope
from app.domains.tr069.exceptions import Tr069DeviceNotFoundError
from tests.unit.isp_partner_fixtures import (
    CFG_A1,
    CFG_B1,
    CPE_A,
    CPE_A_UNASSIGNED,
    CPE_B,
    CUST_A1,
    CUST_A2,
    CUST_B1,
    ISP_A,
    ISP_B,
    LOC_A1,
    LOC_B1,
    RTR_A1,
    RTR_B1,
    USER_A,
    context,
    estate,
    org,
)


class TestAssertCustomer:
    async def test_own_child_resolves(self) -> None:
        repo = estate()
        assert (await IspScope.assert_customer(context(repo), CUST_A1)).id == CUST_A1

    @pytest.mark.parametrize(
        "target", [CUST_B1, ISP_A, ISP_B, uuid.uuid4()], ids=["other-isp", "self", "isp-b", "unknown"]
    )
    async def test_anything_else_is_404(self, target) -> None:
        with pytest.raises(IspCustomerNotFoundError) as err:
            await IspScope.assert_customer(context(estate()), target)
        assert err.value.status_code == 404
        assert err.value.data["code"] == "ISP_CUSTOMER_NOT_FOUND"

    async def test_msp_child_archived_and_deleted_are_404(self) -> None:
        repo = estate()
        repo.orgs[CUST_A1].org_type = "msp"
        repo.orgs[CUST_A2].status = "archived"
        isp = context(repo)
        for target in (CUST_A1, CUST_A2):
            with pytest.raises(IspCustomerNotFoundError):
                await IspScope.assert_customer(isp, target)

    async def test_grandchild_is_404(self) -> None:
        repo = estate()
        grandchild = uuid.uuid4()
        repo.orgs[grandchild] = org(grandchild, parent=CUST_A1)
        with pytest.raises(IspCustomerNotFoundError):
            await IspScope.assert_customer(context(repo), grandchild)

    async def test_confinement_is_404_not_403(self) -> None:
        isp = context(estate(), role="isp-technician", confined={CUST_A1})
        assert await IspScope.assert_customer(isp, CUST_A1)
        with pytest.raises(IspCustomerNotFoundError):
            await IspScope.assert_customer(isp, CUST_A2)


class TestDerivedEntities:
    async def test_location_router_config_cpe_of_isp_b_are_404(self) -> None:
        isp = context(estate())
        with pytest.raises(IspLocationNotFoundError):
            await IspScope.assert_location(isp, LOC_B1)
        with pytest.raises(IspRouterNotFoundError):
            await IspScope.assert_router(isp, RTR_B1)
        with pytest.raises(IspPortalConfigNotFoundError):
            await IspScope.assert_portal_config(isp, CFG_B1)
        with pytest.raises(Tr069DeviceNotFoundError):
            await IspScope.assert_cpe(isp, CPE_B)

    async def test_own_entities_resolve(self) -> None:
        isp = context(estate())
        assert (await IspScope.assert_location(isp, LOC_A1)).id == LOC_A1
        assert (await IspScope.assert_router(isp, RTR_A1)).id == RTR_A1
        assert (await IspScope.assert_portal_config(isp, CFG_A1)).id == CFG_A1
        assert (await IspScope.assert_cpe(isp, CPE_A)).id == CPE_A
        assert (await IspScope.assert_cpe(isp, CPE_A_UNASSIGNED)).id == CPE_A_UNASSIGNED

    async def test_confined_technician_cannot_reach_other_customers_router(self) -> None:
        isp = context(estate(), role="isp-technician", confined={CUST_A2})
        with pytest.raises(IspRouterNotFoundError):
            await IspScope.assert_router(isp, RTR_A1)
        with pytest.raises(Tr069DeviceNotFoundError):
            await IspScope.assert_cpe(isp, CPE_A)
        # Unassigned CPEs belong to no customer: a confined user never sees them.
        with pytest.raises(Tr069DeviceNotFoundError):
            await IspScope.assert_cpe(isp, CPE_A_UNASSIGNED)

    async def test_optional_filters_imply_customer_and_refuse_mismatch(self) -> None:
        isp = context(estate())
        assert await IspScope.optional_filters(isp, isp_router_id=RTR_A1) == (
            CUST_A1,
            LOC_A1,
            RTR_A1,
        )
        with pytest.raises(IspLocationNotFoundError):
            await IspScope.optional_filters(isp, isp_customer_id=CUST_A2, isp_location_id=LOC_A1)

    async def test_child_ids_respect_confinement_and_can_be_empty(self) -> None:
        repo = estate()
        assert await context(repo).child_ids() == [CUST_A1, CUST_A2]
        assert await context(repo, role="isp-noc", confined={CUST_A2}).child_ids() == [CUST_A2]
        fresh = uuid.uuid4()
        repo.orgs[fresh] = org(fresh, parent=None, org_type="msp")
        repo.profiles[fresh] = repo.profiles[ISP_A]
        assert await context(repo, isp=fresh).child_ids() == []


# -- RequireIspPartner --------------------------------------------------------


def _assignment(slug, *, org_id=ISP_A, scope_type="organization", role_scope="organization"):
    return SimpleNamespace(
        role=SimpleNamespace(
            id=uuid.uuid4(), slug=slug, organization_id=None, scope_type=role_scope
        ),
        assignment=SimpleNamespace(scope_type=scope_type, organization_id=org_id),
    )


@pytest.fixture
def roles(monkeypatch):
    held: list = []

    class FakeResolver:
        def __init__(self, repository) -> None:
            pass

        async def get_active_assignments(self, user_id):
            return held

    monkeypatch.setattr(deps, "RoleResolver", FakeResolver)
    return held


def _user():
    return SimpleNamespace(id=str(USER_A))


class TestRequireIspPartner:
    async def test_owner_gets_context(self, roles) -> None:
        roles.append(_assignment("isp-owner"))
        ctx = await deps.RequireIspPartner(ISP_A, _user(), None, estate())
        assert ctx.isp_org_id == ISP_A and ctx.role_slug == "isp-owner"
        assert ctx.confined_customer_ids is None

    async def test_global_caller_is_refused(self, roles) -> None:
        roles.append(_assignment("isp-owner"))
        roles.append(_assignment("super-admin", org_id=None, scope_type="global", role_scope="global"))
        with pytest.raises(IspRoleRequiredError):
            await deps.RequireIspPartner(ISP_A, _user(), None, estate())

    async def test_customer_org_owner_naming_own_org_is_role_required(self, roles) -> None:
        """BE-T 12."""
        roles.append(_assignment("organization-owner", org_id=CUST_A1))
        with pytest.raises(IspRoleRequiredError) as err:
            await deps.RequireIspPartner(CUST_A1, _user(), None, estate())
        assert err.value.status_code == 403
        assert err.value.data["code"] == "ISP_ROLE_REQUIRED"

    async def test_isp_role_on_another_org_does_not_count(self, roles) -> None:
        roles.append(_assignment("isp-owner", org_id=ISP_B))
        with pytest.raises(IspRoleRequiredError):
            await deps.RequireIspPartner(ISP_A, _user(), None, estate())

    async def test_no_profile_is_partner_required(self, roles) -> None:
        repo = estate()
        del repo.profiles[ISP_A]
        roles.append(_assignment("isp-owner"))
        with pytest.raises(IspPartnerRequiredError):
            await deps.RequireIspPartner(ISP_A, _user(), None, repo)

    @pytest.mark.parametrize("what", ["profile", "org_status", "org_type"])
    async def test_suspended_or_wrong_shape_is_suspended(self, roles, what) -> None:
        repo = estate()
        if what == "profile":
            repo.profiles[ISP_A].status = "suspended"
        elif what == "org_status":
            repo.orgs[ISP_A].status = "suspended"
        else:
            repo.orgs[ISP_A].org_type = "standard"
        roles.append(_assignment("isp-owner"))
        with pytest.raises(IspPartnerSuspendedError):
            await deps.RequireIspPartner(ISP_A, _user(), None, repo)

    async def test_confinement_loaded_for_confinable_roles_only(self, roles) -> None:
        repo = estate()
        repo.scopes[(ISP_A, USER_A)] = {CUST_A1}
        roles.append(_assignment("isp-technician"))
        ctx = await deps.RequireIspPartner(ISP_A, _user(), None, repo)
        assert ctx.confined_customer_ids == frozenset({CUST_A1})
        roles[:] = [_assignment("isp-admin")]
        ctx = await deps.RequireIspPartner(ISP_A, _user(), None, repo)
        assert ctx.confined_customer_ids is None


class TestRejectLocationRouterHeaders:
    @pytest.mark.parametrize("header", ["X-Location-Id", "X-Router-Id"])
    async def test_scope_headers_are_400(self, header) -> None:
        request = SimpleNamespace(headers={header: str(uuid.uuid4())})
        with pytest.raises(IspScopeHeadersNotAllowedError) as err:
            await deps.RejectLocationRouterHeaders(request)  # type: ignore[arg-type]
        assert err.value.status_code == 400

    async def test_absent_passes(self) -> None:
        await deps.RejectLocationRouterHeaders(SimpleNamespace(headers={}))  # type: ignore[arg-type]

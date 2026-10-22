"""Shared fakes for the ISP partner unit tests. All ids and names are made
up; all data is obviously fake (example.com, RFC 5737 addresses)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from app.domains.isp_partner.dependencies import IspContext

ISP_A = uuid.UUID("00000000-0000-0000-0000-0000000000a0")
ISP_B = uuid.UUID("00000000-0000-0000-0000-0000000000b0")
CUST_A1 = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
CUST_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
CUST_B1 = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
LOC_A1 = uuid.UUID("00000000-0000-0000-0000-00000000a101")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-00000000a201")
LOC_B1 = uuid.UUID("00000000-0000-0000-0000-00000000b101")
RTR_A1 = uuid.UUID("00000000-0000-0000-0000-0000a1010001")
RTR_B1 = uuid.UUID("00000000-0000-0000-0000-0000b1010001")
CFG_A1 = uuid.UUID("00000000-0000-0000-0000-00000c0a0101")
CFG_B1 = uuid.UUID("00000000-0000-0000-0000-00000c0b0101")
CPE_A = uuid.UUID("00000000-0000-0000-0000-0000000c0e0a")
CPE_A_UNASSIGNED = uuid.UUID("00000000-0000-0000-0000-0000000c0e0f")
CPE_B = uuid.UUID("00000000-0000-0000-0000-0000000c0e0b")
USER_A = uuid.UUID("00000000-0000-0000-0000-00000000aaaa")
PLAN = uuid.UUID("00000000-0000-0000-0000-0000000091a0")

NOW = datetime(2026, 10, 22, 6, 0, tzinfo=UTC)


def org(
    id: uuid.UUID,
    *,
    parent: uuid.UUID | None,
    org_type: str = "standard",
    status: str = "active",
    name: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        name=name or f"Org {str(id)[-4:]}",
        slug=f"org-{str(id)[-4:]}",
        legal_name=None,
        org_type=org_type,
        status=status,
        parent_organization_id=parent,
        contact_email="ops@example.com",
        contact_phone=None,
        timezone="Asia/Kolkata",
        settings={},
        is_deleted=False,
        created_at=NOW,
        updated_at=NOW,
    )


@dataclass
class FakeIspRepository:
    orgs: dict[uuid.UUID, Any] = field(default_factory=dict)
    locations: dict[uuid.UUID, Any] = field(default_factory=dict)
    routers: dict[uuid.UUID, Any] = field(default_factory=dict)
    configs: dict[uuid.UUID, Any] = field(default_factory=dict)
    cpes: dict[uuid.UUID, Any] = field(default_factory=dict)
    profiles: dict[uuid.UUID, Any] = field(default_factory=dict)
    scopes: dict[tuple[uuid.UUID, uuid.UUID], set[uuid.UUID]] = field(
        default_factory=dict
    )
    session: Any = None

    async def get_organization(self, organization_id):
        return self.orgs.get(organization_id)

    async def get_location(self, location_id):
        return self.locations.get(location_id)

    async def get_router(self, router_id):
        return self.routers.get(router_id)

    async def get_portal_config(self, config_id):
        return self.configs.get(config_id)

    async def get_cpe(self, cpe_id):
        return self.cpes.get(cpe_id)

    async def get_profile(self, organization_id):
        return self.profiles.get(organization_id)

    async def confined_customer_ids(self, isp_org_id, user_id):
        return set(self.scopes.get((isp_org_id, user_id), set()))

    async def child_ids(self, isp_org_id):
        return sorted(
            (
                o.id
                for o in self.orgs.values()
                if o.parent_organization_id == isp_org_id
                and o.org_type == "standard"
                and o.status != "archived"
                and not o.is_deleted
            ),
            key=lambda i: self.orgs[i].name,
        )

    async def names(self, model, ids):
        out = {}
        for i in ids:
            for table in (self.orgs, self.locations):
                if i in table:
                    out[i] = table[i].name
        return out


def estate() -> FakeIspRepository:
    """Two ISPs. A has customers A1, A2; B has B1."""
    repo = FakeIspRepository()
    repo.orgs[ISP_A] = org(ISP_A, parent=None, org_type="msp", name="Airlink")
    repo.orgs[ISP_B] = org(ISP_B, parent=None, org_type="msp", name="Bharat Net")
    repo.orgs[CUST_A1] = org(CUST_A1, parent=ISP_A, name="Cafe A1")
    repo.orgs[CUST_A2] = org(CUST_A2, parent=ISP_A, name="Hostel A2")
    repo.orgs[CUST_B1] = org(CUST_B1, parent=ISP_B, name="Office B1")
    for loc, owner in ((LOC_A1, CUST_A1), (LOC_A2, CUST_A2), (LOC_B1, CUST_B1)):
        repo.locations[loc] = SimpleNamespace(
            id=loc, organization_id=owner, name=f"Loc {str(loc)[-4:]}", is_deleted=False
        )
    for rtr, loc, owner in ((RTR_A1, LOC_A1, CUST_A1), (RTR_B1, LOC_B1, CUST_B1)):
        repo.routers[rtr] = SimpleNamespace(
            id=rtr, organization_id=owner, location_id=loc, name="hEX", is_deleted=False
        )
    repo.configs[CFG_A1] = SimpleNamespace(
        id=CFG_A1, organization_id=CUST_A1, is_deleted=False
    )
    repo.configs[CFG_B1] = SimpleNamespace(
        id=CFG_B1, organization_id=CUST_B1, is_deleted=False
    )
    repo.cpes[CPE_A] = SimpleNamespace(
        id=CPE_A,
        isp_organization_id=ISP_A,
        customer_organization_id=CUST_A1,
        is_deleted=False,
    )
    repo.cpes[CPE_A_UNASSIGNED] = SimpleNamespace(
        id=CPE_A_UNASSIGNED,
        isp_organization_id=ISP_A,
        customer_organization_id=None,
        is_deleted=False,
    )
    repo.cpes[CPE_B] = SimpleNamespace(
        id=CPE_B,
        isp_organization_id=ISP_B,
        customer_organization_id=CUST_B1,
        is_deleted=False,
    )
    for isp in (ISP_A, ISP_B):
        repo.profiles[isp] = SimpleNamespace(
            organization_id=isp,
            status="active",
            max_customers=None,
            default_customer_plan_id=PLAN,
            support_phone="+911140000000",
        )
    return repo


def context(
    repo: FakeIspRepository,
    *,
    isp: uuid.UUID = ISP_A,
    role: str = "isp-owner",
    confined: set[uuid.UUID] | None = None,
) -> IspContext:
    return IspContext(
        isp_org_id=isp,
        user_id=USER_A,
        role_slug=role,
        role_id=uuid.uuid4(),
        confined_customer_ids=frozenset(confined) if confined is not None else None,
        organization=repo.orgs[isp],
        profile=repo.profiles[isp],
        repository=repo,
    )

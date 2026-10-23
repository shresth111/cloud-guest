"""Body-id defect class: every id-shaped field in a twin's request body is
declared (``TwinSpec.body_ids``) and enforced against the resolved target.

See ``app/domains/isp_partner/twin_body.py`` for the modes.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest
from pydantic import BaseModel

from app.domains.isp_partner.exceptions import (
    IspBadRequestError,
    IspLocationNotFoundError,
    IspRouterNotFoundError,
)
from app.domains.isp_partner.twin_body import BodyId, apply_body_ids, is_id_shaped
from app.domains.isp_partner.twins_all import ALL_TWINS as VENUE_TWINS
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    LOC_A1,
    RTR_A1,
    RTR_B1,
    context,
    estate,
)


def _body_rows():
    for spec in VENUE_TWINS:
        for p in spec.params:
            if p.source == "body":
                yield spec, p


@pytest.mark.parametrize(
    ("spec", "param"),
    list(_body_rows()),
    ids=[f"{s.method} {s.path}" for s, _ in _body_rows()],
)
def test_every_id_shaped_body_field_is_declared(spec, param) -> None:
    fields = set(getattr(param.annotation, "model_fields", {}))
    id_fields = {f for f in fields if is_id_shaped(f)}
    declared = {b.field for b in spec.body_ids if b.param == param.name}
    missing = id_fields - declared
    assert not missing, (
        f"{spec.method} {spec.path}: body id fields {sorted(missing)} reach the "
        "original handler unchecked; declare them in body_ids"
    )
    assert declared <= fields, f"stale body_ids: {sorted(declared - fields)}"


def test_the_coverage_check_bites() -> None:
    spec, param = next(
        (s, p) for s, p in _body_rows() if any(b.mode == "router" for b in s.body_ids)
    )
    broken = replace(spec, body_ids=())
    fields = {f for f in param.annotation.model_fields if is_id_shaped(f)}
    assert fields - {b.field for b in broken.body_ids}


class _Body(BaseModel):
    router_id: str | None = None
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    scope_type: str = "organization"
    scope_id: uuid.UUID | None = None
    target_type: str = "none"
    target_id: uuid.UUID | None = None


async def _apply(body_ids, body):
    kwargs = {"payload": body}
    await apply_body_ids(body_ids, kwargs, context(estate()), CUST_A1, LOC_A1)
    return kwargs["payload"]


async def test_router_from_another_customer_is_404() -> None:
    with pytest.raises(IspRouterNotFoundError):
        await _apply((BodyId("router_id", "router"),), _Body(router_id=str(RTR_B1)))


async def test_router_of_this_location_passes() -> None:
    out = await _apply((BodyId("router_id", "router"),), _Body(router_id=str(RTR_A1)))
    assert out.router_id == str(RTR_A1)


async def test_org_and_location_are_forced_to_the_target() -> None:
    other = uuid.uuid4()
    out = await _apply(
        (
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        _Body(organization_id=other, location_id=other),
    )
    assert out.organization_id == CUST_A1
    assert out.location_id == LOC_A1


@pytest.mark.parametrize("scope_type", ["global", "msp", "platform"])
async def test_policy_scope_outside_the_customer_is_refused(scope_type) -> None:
    with pytest.raises(IspBadRequestError):
        await _apply(
            (BodyId("scope_id", "policy_scope"),),
            _Body(scope_type=scope_type, scope_id=uuid.uuid4()),
        )


async def test_policy_scope_other_location_is_404() -> None:
    with pytest.raises(IspLocationNotFoundError):
        await _apply(
            (BodyId("scope_id", "policy_scope"),),
            _Body(scope_type="location", scope_id=uuid.uuid4()),
        )


async def test_policy_scope_organization_is_forced_to_the_customer() -> None:
    out = await _apply(
        (BodyId("scope_id", "policy_scope"),),
        _Body(scope_type="organization", scope_id=uuid.uuid4()),
    )
    assert out.scope_id == CUST_A1


@pytest.mark.parametrize("target_type", ["user", "role"])
async def test_policy_target_user_or_role_is_refused(target_type) -> None:
    with pytest.raises(IspBadRequestError):
        await _apply(
            (BodyId("target_id", "policy_target"),),
            _Body(target_type=target_type, target_id=uuid.uuid4()),
        )

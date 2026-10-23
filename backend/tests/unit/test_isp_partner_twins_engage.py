"""B3 twins: auto_twin derivation and the ISP voucher-manage answer."""

from __future__ import annotations

import pytest

from app.domains.isp_partner.constants import ISP_ENGAGE_MANAGE
from app.domains.isp_partner.twin_auto import auto_twin
from app.domains.isp_partner.twins_engage import (
    ENGAGE_TWINS,
    get_isp_voucher_manage_bypass,
)
from app.domains.rbac.enums import ScopeType
from app.domains.voucher import router as voucher_routes
from tests.unit.isp_partner_fixtures import ISP_A, context, estate


class _Validator:
    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.calls: list[tuple] = []

    async def has_permission(self, user_id, key, *, scope_type, scope_context):
        self.calls.append((user_id, key, scope_type, scope_context.organization_id))
        return self.answer


@pytest.mark.parametrize("answer", [True, False])
async def test_voucher_manage_is_asked_in_isp_terms(answer) -> None:
    v = _Validator(answer)
    got = await get_isp_voucher_manage_bypass(isp=context(estate()), access_validator=v)
    assert got is answer
    (_, key, scope, org) = v.calls[0]
    assert key == ISP_ENGAGE_MANAGE
    assert scope == ScopeType.ORGANIZATION
    assert org == ISP_A


def test_voucher_create_uses_the_isp_answer() -> None:
    row = next(s for s in ENGAGE_TWINS if s.path == "/venue/voucher-batches")
    assert row.deps["has_manage_permission"] is get_isp_voucher_manage_bypass


def test_auto_twin_refuses_an_unknown_override() -> None:
    with pytest.raises(ValueError):
        auto_twin(
            "POST",
            "/venue/voucher-batches",
            voucher_routes.create_voucher_batch,
            "isp_engage.create",
            deps_override={"nope": object},
        )


def test_auto_twin_forces_location_and_never_exposes_scope_aliases() -> None:
    for spec in ENGAGE_TWINS:
        exposed = {p.name for p in spec.params} | {e.name for e in spec.extras}
        assert not exposed & {"organization_id", "customer_id", "location_id", "router_id"}
        if "location_id" in spec.inject:
            assert spec.inject["location_id"] == ("location",)

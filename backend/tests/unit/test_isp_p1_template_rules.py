"""P1-1: device rules on speed templates (``/isp/speed-groups/{id}/device-rules``).

Flag default OFF -> 404; another ISP's template -> 404; impossible
combinations refused; the diff only names fields that move and treats a
package with no policy row as the policy defaults. The route-table rules
(guard stack, no scope-alias names, permission coverage) are walked for every
isp_partner route by ``test_isp_partner_guards`` / ``test_route_permission_coverage``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import p1_templates_router as pt
from app.domains.isp_partner.exceptions import IspBadRequestError
from app.domains.isp_partner.p1_config import get_p1_settings
from app.domains.isp_partner.plans_service import IspSpeedGroupNotFoundError

ISP, OTHER = uuid.uuid4(), uuid.uuid4()


class _Db:
    def __init__(self, *rows):
        self.rows = {r.id: r for r in rows}

    async def get(self, _model, key):
        return self.rows.get(key)


def _isp():
    return SimpleNamespace(isp_org_id=ISP, user_id=uuid.uuid4())


def _rules(**kw):
    base = {
        "max_devices": 3,
        "mac_bind_count": 2,
        "mac_restriction": True,
        "max_simultaneous": 2,
    }
    base.update(kw)
    return SimpleNamespace(**base)


async def test_flag_defaults_off(monkeypatch) -> None:
    monkeypatch.delenv("ISP_TEMPLATE_RULES_ENABLED", raising=False)
    get_p1_settings.cache_clear()
    assert get_p1_settings().template_rules_enabled is False
    assert get_p1_settings().cycle_basis_enabled is False
    assert get_p1_settings().zone_coupon_rights_enabled is False
    with pytest.raises(HTTPException) as exc:
        await pt.RequireTemplateRulesEnabled()
    assert exc.value.status_code == 404


async def test_flag_on_passes(monkeypatch) -> None:
    monkeypatch.setenv("ISP_TEMPLATE_RULES_ENABLED", "true")
    get_p1_settings.cache_clear()
    try:
        await pt.RequireTemplateRulesEnabled()
    finally:
        get_p1_settings.cache_clear()


@pytest.mark.parametrize(
    "grp",
    [
        SimpleNamespace(id=uuid.uuid4(), is_deleted=False, isp_organization_id=OTHER),
        SimpleNamespace(id=uuid.uuid4(), is_deleted=True, isp_organization_id=ISP),
    ],
)
async def test_other_isp_or_deleted_template_is_404(grp) -> None:
    with pytest.raises(IspSpeedGroupNotFoundError):
        await pt._group(_Db(grp), _isp(), grp.id)


def test_bounds_match_package_form_and_policy() -> None:
    pt.DeviceRulesRequest()
    pt.DeviceRulesRequest(max_devices=50, mac_bind_count=16, max_simultaneous=50)
    for bad in (
        {"max_devices": 0},
        {"max_devices": 51},
        {"mac_bind_count": 17},
        {"max_simultaneous": 0},
        {"fup_limit_mb": 10},  # extra fields are refused, not ignored
    ):
        with pytest.raises(ValidationError):
            pt.DeviceRulesRequest(**bad)


def test_impossible_combinations_refused() -> None:
    with pytest.raises(IspBadRequestError):
        pt.validate_rules(
            {
                "max_devices": 2,
                "mac_bind_count": 0,
                "mac_restriction": True,
                "max_simultaneous": None,
            }
        )
    with pytest.raises(IspBadRequestError):
        pt.validate_rules(
            {
                "max_devices": 2,
                "mac_bind_count": 2,
                "mac_restriction": False,
                "max_simultaneous": 3,
            }
        )
    pt.validate_rules(
        {
            "max_devices": 2,
            "mac_bind_count": 2,
            "mac_restriction": True,
            "max_simultaneous": 2,
        }
    )


def test_changes_without_policy_row_compare_to_defaults() -> None:
    pkg = SimpleNamespace(max_devices=1)
    assert pt.package_changes(pkg, None, _rules()) == {
        "max_devices": {"from": 1, "to": 3},
        "mac_bind_count": {"from": 0, "to": 2},
        "mac_restriction": {"from": False, "to": True},
        "max_simultaneous": {"from": None, "to": 2},
    }
    # default rules on a package with no policy: nothing moves, no row is made
    assert (
        pt.package_changes(
            pkg,
            None,
            _rules(
                max_devices=1,
                mac_bind_count=0,
                mac_restriction=False,
                max_simultaneous=None,
            ),
        )
        == {}
    )


def test_changes_only_names_moving_fields() -> None:
    pkg = SimpleNamespace(max_devices=3)
    policy = SimpleNamespace(
        mac_bind_count=2, mac_restriction=False, max_simultaneous=2
    )
    assert pt.package_changes(pkg, policy, _rules()) == {
        "mac_restriction": {"from": False, "to": True}
    }


def test_view_shape_unconfigured() -> None:
    gid = uuid.uuid4()
    assert pt.rules_view(gid, None) == {
        "speed_group_id": str(gid),
        "configured": False,
        "max_devices": 1,
        "mac_bind_count": 0,
        "mac_restriction": False,
        "max_simultaneous": None,
    }


def test_rule_fields_are_the_package_and_policy_fields() -> None:
    from app.domains.isp_partner.enforcement_models import IspPackagePolicy
    from app.domains.isp_partner.plans_models import IspPackage

    assert hasattr(IspPackage, "max_devices")
    for f in pt._POLICY_RULE_FIELDS:
        assert hasattr(IspPackagePolicy, f)
        col = IspPackagePolicy.__table__.c[f]
        default = pt._POLICY_DEFAULTS[f]
        if default is None:
            assert col.nullable
        else:
            assert str(col.server_default.arg).strip("'") in (
                str(default).lower(),
                str(default),
            )

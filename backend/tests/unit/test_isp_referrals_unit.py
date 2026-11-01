"""REFERRAL-1 route surface, grants and the pass with the flag off."""

from __future__ import annotations


def test_routes_are_flagged() -> None:
    from app.domains.isp_partner.referrals_config import RequireReferralsEnabled
    from app.domains.isp_partner.referrals_router import referrals_router

    paths = [r.path for r in referrals_router.routes]
    for r in referrals_router.routes:
        assert r.dependencies[0].dependency is RequireReferralsEnabled, r.path
    assert paths.index("/referrals/settings") < paths.index("/referrals/{referral_id}")


def test_settings_are_owner_admin_only() -> None:
    from app.domains.isp_partner.rbac_roles import ROLES

    holders = {r.slug for r in ROLES if "isp_referrals.manage" in r.permission_keys}
    assert holders == {"isp-owner", "isp-admin"}


async def test_pass_is_a_no_op_with_the_flag_off(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.isp_partner import referrals_service as svc

    class _Off:
        referrals_enabled = False

    monkeypatch.setattr(svc, "get_referrals_settings", lambda: _Off())

    class _NoSession:
        async def execute(self, *a, **k):  # noqa: ANN002, ANN003, ANN202
            raise AssertionError("must not touch the database")

    assert await svc.run_referrals(_NoSession()) == {
        "referrals": 0,
        "errors": 0,
        "pages": 0,
    }

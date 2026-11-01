"""QUEUED-RENEWAL route surface + the activation pass with the flag off."""

from __future__ import annotations

from app.domains.isp_partner.queued_renewal_config import RequireQueuedRenewalEnabled
from app.domains.isp_partner.queued_renewal_router import queued_renewal_router


def test_routes_are_flagged_and_use_the_renew_revert_keys() -> None:
    seen = {}
    for r in queued_renewal_router.routes:
        assert r.dependencies[0].dependency is RequireQueuedRenewalEnabled, r.path
        seen[(sorted(r.methods)[0], r.path)] = r
    assert set(seen) == {
        ("GET", "/queued-renewals"),
        ("GET", "/subscribers/{subscriber_id}/queued-renewals"),
        ("POST", "/subscribers/{subscriber_id}/queued-renewals"),
        ("POST", "/subscribers/{subscriber_id}/queued-renewals/{queue_id}/cancel"),
    }


async def test_activation_pass_is_a_no_op_with_the_flag_off(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.isp_partner import queued_renewal_service as svc

    class _Off:
        queued_renewal_enabled = False

    monkeypatch.setattr(svc, "get_queued_renewal_settings", lambda: _Off())

    class _NoSession:
        async def execute(self, *a, **k):  # noqa: ANN002, ANN003, ANN202
            raise AssertionError("must not touch the database")

    out = await svc.run_queued_renewals(_NoSession())
    assert out == {"activated": 0, "cancelled": 0, "errors": 0}

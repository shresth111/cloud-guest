"""SUB360-2 route guards: both workbench routes are flag-gated, ISP-guarded,
and use the subscriber permissions (read / update)."""

from __future__ import annotations


def test_workbench_routes_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.workbench_router import (
        RequireWorkbenchEnabled,
        workbench_router,
    )

    seen = {}
    for r in workbench_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireWorkbenchEnabled in deps, r.path
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names, r.path
        seen[(r.path, tuple(sorted(r.methods)))] = r
    assert set(seen) == {
        ("/subscribers/{subscriber_id}/workbench", ("GET",)),
        ("/subscribers/{subscriber_id}/workbench/disconnect", ("POST",)),
    }


def test_disconnect_body_is_strict() -> None:
    import pytest
    from pydantic import ValidationError

    from app.domains.isp_partner.workbench_router import DisconnectRequest

    assert DisconnectRequest().session_id is None
    with pytest.raises(ValidationError):
        DisconnectRequest(bogus=1)  # type: ignore[call-arg]


def test_flag_defaults_off(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.isp_partner.workbench_router import get_workbench_settings

    monkeypatch.delenv("ISP_SUB360_WORKBENCH_ENABLED", raising=False)
    get_workbench_settings.cache_clear()
    assert get_workbench_settings().sub360_workbench_enabled is False
    get_workbench_settings.cache_clear()

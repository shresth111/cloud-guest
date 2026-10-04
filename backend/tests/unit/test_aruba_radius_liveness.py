"""P1-E RADIUS liveness for NAS-only (Aruba Instant On) fleet rows.

* the shared Aruba listener stamps ``radius_nas_clients.last_request_at`` /
  ``last_accounting_at`` (throttled, conditional UPDATE) after a resolved
  packet, never after a refusal, and the per-venue routes never stamp;
* ``RouterResponse.last_radius_at`` is populated ONLY for NAS-only rows:
  a MikroTik or Omada row is null, and the activity lookup is not even
  asked about them (their serialization is unchanged).
"""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from tests.unit.test_router import FakeIntegration, make_router, make_service

AT = datetime(2026, 10, 4, 6, 0, tzinfo=UTC)


async def _row(repo, vendor: str):  # noqa: ANN001, ANN202
    router_device = await make_router(
        repo,
        location_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        serial_number=f"SN-{uuid.uuid4()}",
        mac_address="54:F0:B1:C8:A9:0A",
    )
    router_device.vendor = vendor
    return router_device


class TestControllerContextLastRadius:
    async def test_nas_only_row_carries_last_radius_at(self) -> None:
        service, repo, *_ = make_service()
        aruba = await _row(repo, "aruba_instant_on")
        asked: list[list[uuid.UUID]] = []

        async def lookup(ids):  # noqa: ANN001, ANN202
            asked.append(list(ids))
            return {aruba.id: AT}

        repo.radius_activity_for_routers = lookup
        (ctx,) = (await service.controller_context([aruba])).values()
        assert ctx.last_radius_at == AT
        assert ctx.state == "no_controller_api"
        assert asked == [[aruba.id]]

    async def test_mikrotik_and_omada_never_asked_and_null(self) -> None:
        service, repo, *_ = make_service()
        mikrotik = await _row(repo, "mikrotik")
        omada = await _row(repo, "tplink_omada")
        repo.integrations[omada.id] = FakeIntegration()
        asked: list[Any] = []

        async def lookup(ids):  # noqa: ANN001, ANN202
            asked.append(list(ids))
            return {mikrotik.id: AT, omada.id: AT}

        repo.radius_activity_for_routers = lookup
        contexts = await service.controller_context([mikrotik, omada])
        assert contexts[mikrotik.id].last_radius_at is None
        assert contexts[omada.id].last_radius_at is None
        assert asked == []

    async def test_mixed_page_asks_only_for_the_nas_only_ids(self) -> None:
        service, repo, *_ = make_service()
        aruba = await _row(repo, "aruba_instant_on")
        omada = await _row(repo, "tplink_omada")
        repo.integrations[omada.id] = FakeIntegration()
        asked: list[Any] = []

        async def lookup(ids):  # noqa: ANN001, ANN202
            asked.append(list(ids))
            return {aruba.id: AT}

        repo.radius_activity_for_routers = lookup
        contexts = await service.controller_context([aruba, omada])
        assert asked == [[aruba.id]]
        assert contexts[aruba.id].last_radius_at == AT
        assert contexts[omada.id].last_radius_at is None

    async def test_router_response_field_null_for_mikrotik(self) -> None:
        from app.domains.router.router import _router_response
        from app.domains.router.service import ControllerContext

        service, repo, *_ = make_service()
        mikrotik = await _row(repo, "mikrotik")
        resp = _router_response(mikrotik, ControllerContext())
        assert resp.last_radius_at is None
        aruba = await _row(repo, "aruba_instant_on")
        resp = _router_response(aruba, ControllerContext(last_radius_at=AT))
        assert resp.last_radius_at == AT


class TestStamping:
    async def test_stamp_issues_conditional_update(self) -> None:
        from app.domains.guest.router import _stamp_nas_activity

        stmts: list[Any] = []

        class _Db:
            async def execute(self, stmt):  # noqa: ANN001, ANN202
                stmts.append(stmt)

        service = SimpleNamespace(repository=SimpleNamespace(session=_Db()))
        nas = SimpleNamespace(id=uuid.uuid4())
        await _stamp_nas_activity(service, nas, column="last_accounting_at")
        (stmt,) = stmts
        sql = str(stmt.compile())
        assert "UPDATE radius_nas_clients" in sql
        assert "last_accounting_at" in sql and "WHERE" in sql

    async def test_stamp_never_raises(self) -> None:
        from app.domains.guest.router import _stamp_nas_activity

        class _Db:
            async def execute(self, stmt):  # noqa: ANN001, ANN202
                raise RuntimeError("db down")

        service = SimpleNamespace(repository=SimpleNamespace(session=_Db()))
        await _stamp_nas_activity(
            service, SimpleNamespace(id=uuid.uuid4()), column="last_request_at"
        )
        # No session (unit fake) -> silent no-op.
        await _stamp_nas_activity(
            SimpleNamespace(), SimpleNamespace(id=uuid.uuid4()), column="x"
        )

    def test_only_shared_routes_stamp_and_only_after_resolve(self) -> None:
        from app.domains.guest import router as guest_router

        for fn in (
            guest_router.radius_aruba_shared_authorize,
            guest_router.radius_aruba_shared_accounting,
        ):
            src = inspect.getsource(fn)
            assert "_stamp_nas_activity" in src
            # after the refusal branch, so a refused packet stamps nothing
            assert src.index("log_rejection") < src.index("_stamp_nas_activity")
        for fn in (guest_router.radius_accounting, guest_router._radius_accounting):
            assert "_stamp_nas_activity" not in inspect.getsource(fn)
        per_venue_authorize = next(
            obj
            for name, obj in vars(guest_router).items()
            if name == "radius_authorize"
        )
        assert "_stamp_nas_activity" not in inspect.getsource(per_venue_authorize)

"""P1-H (BE) + P2-Q: RouterOS-session operations refuse an Aruba Instant On
(NAS-only) row with 409 ``NAS_ONLY_DEVICE`` instead of a misleading "missing
credentials" answer. MikroTik behaviour is unchanged (the existing
connected-devices and router suites cover it; one parity case is repeated
here).
"""

from __future__ import annotations

import inspect

import pytest

from app.domains.connected_devices.exceptions import (
    ConnectedDeviceMissingCredentialsError,
)
from app.domains.router.exceptions import RouterNasOnlyOperationError
from tests.unit.test_connected_devices import _make_router, make_harness


def _aruba():  # noqa: ANN202
    router = _make_router()
    router.vendor = "aruba_instant_on"
    router.api_username = None
    router.api_credentials_encrypted = None
    router.management_ip_address = None
    return router


class TestConnectedDevices:
    async def test_sync_refuses_nas_only_before_credentials(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_aruba(), secret=None)
        with pytest.raises(RouterNasOnlyOperationError) as exc:
            await h.service.sync_router(router.id)
        assert exc.value.status_code == 409
        assert exc.value.data == {
            "code": "NAS_ONLY_DEVICE",
            "operation": "connected_devices",
        }

    async def test_mikrotik_without_credentials_unchanged(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router(), secret=None)
        with pytest.raises(ConnectedDeviceMissingCredentialsError):
            await h.service.sync_router(router.id)


class TestReboot:
    def test_reboot_refuses_nas_only_before_credentials(self) -> None:
        from app.domains.router import router as router_module

        src = inspect.getsource(router_module.reboot_router)
        assert "is_nas_only(router_row)" in src
        assert src.index("is_nas_only(router_row)") < src.index(
            "get_decrypted_api_secret"
        )

    async def test_reboot_route_raises_for_aruba(self) -> None:
        from types import SimpleNamespace

        from app.domains.router.router import reboot_router

        aruba = _aruba()

        class _Svc:
            async def get_router(self, router_id, **_):  # noqa: ANN001, ANN003, ANN202
                return aruba

            def get_decrypted_api_secret(self, row):  # noqa: ANN001, ANN202
                raise AssertionError("must not reach credentials")

        request = SimpleNamespace(state=SimpleNamespace(request_id="t"))
        with pytest.raises(RouterNasOnlyOperationError) as exc:
            await reboot_router(
                request, aruba.id, requesting_organization_id=None,
                router_service=_Svc(),
            )
        assert exc.value.data["operation"] == "reboot"

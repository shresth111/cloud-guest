"""Registry wiring, contract conformance, controller identity, and purity."""

from __future__ import annotations

import inspect
import random

import httpx
import pytest

from wyfy_device_gateway.contract import DeviceVendor, UnsupportedVendorError
from wyfy_device_gateway.controller_contract import (
    ControllerAdapter,
    ControllerAuthMode,
    ControllerInfo,
    ControllerVendor,
)
from wyfy_device_gateway.omada import OmadaControllerAdapter as ExportedAdapter
from wyfy_device_gateway.omada.adapter import (
    MIN_OPENAPI_VERSION,
    OmadaControllerAdapter,
)
from wyfy_device_gateway.omada.errors import (
    OmadaInvalidControllerError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.registry import (
    get_adapter,
    get_controller_adapter,
    list_supported_controller_vendors,
    list_supported_vendors,
)
from wyfy_device_gateway.stub_adapters import TpLinkAdapter

from omada_support import OMADAC_ID, FakeOmadaController, envelope, make_creds, no_sleep

#: Exactly the surface contract section 2 specifies.
CONTRACT_METHODS = [
    "get_controller_info",
    "test_connection",
    "list_sites",
    "get_site",
    "list_ssids",
    "list_devices",
    "list_clients",
    "get_client",
    "authorize_guest",
    "deauthorize_guest",
]


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(), sleep=no_sleep, rng=random.Random(9)
    )


# --- registry --------------------------------------------------------------


def test_get_controller_adapter_returns_the_real_omada_adapter():
    adapter = get_controller_adapter(ControllerVendor.TPLINK_OMADA)
    assert isinstance(adapter, OmadaControllerAdapter)
    assert isinstance(adapter, ControllerAdapter)
    assert adapter.vendor == ControllerVendor.TPLINK_OMADA


def test_list_supported_controller_vendors():
    assert list_supported_controller_vendors() == [ControllerVendor.TPLINK_OMADA]


def test_unregistered_controller_vendor_raises():
    with pytest.raises(UnsupportedVendorError):
        get_controller_adapter("not_a_vendor")  # type: ignore[arg-type]


def test_the_registry_returns_one_shared_instance():
    """A new instance per call would throw away the session cache."""
    assert get_controller_adapter(ControllerVendor.TPLINK_OMADA) is get_controller_adapter(
        ControllerVendor.TPLINK_OMADA
    )


def test_package_export_matches_the_adapter_module():
    assert ExportedAdapter is OmadaControllerAdapter


# --- the existing router registry is untouched ----------------------------


def test_device_registry_is_unchanged():
    assert list_supported_vendors() == sorted(DeviceVendor, key=lambda v: v.value)


def test_tplink_device_stub_is_still_a_stub():
    """The per-device TP-Link stub must stay a stub. The real Omada work is
    controller-level and is reached only via get_controller_adapter."""
    stub = get_adapter(DeviceVendor.TPLINK_OMADA)
    assert isinstance(stub, TpLinkAdapter)
    assert all(value is False for value in stub.capabilities().values())


# --- contract conformance --------------------------------------------------


def test_adapter_implements_every_contract_method_as_async():
    adapter = OmadaControllerAdapter()
    for name in CONTRACT_METHODS:
        method = getattr(adapter, name, None)
        assert method is not None, f"missing contract method {name}"
        assert inspect.iscoroutinefunction(method), f"{name} must be async"


def test_every_contract_method_takes_creds_first():
    adapter = OmadaControllerAdapter()
    for name in CONTRACT_METHODS:
        params = list(inspect.signature(getattr(adapter, name)).parameters)
        assert params[0] == "creds", f"{name} must take creds first, got {params}"


def test_authorize_guest_signature_matches_the_contract():
    sig = inspect.signature(OmadaControllerAdapter().authorize_guest)
    assert list(sig.parameters) == [
        "creds",
        "ctx",
        "duration_seconds",
        "down_kbps",
        "up_kbps",
    ]
    assert sig.parameters["down_kbps"].default is None
    assert sig.parameters["up_kbps"].default is None


# --- controller info -------------------------------------------------------


async def test_get_controller_info_reads_api_info_without_authenticating():
    controller = FakeOmadaController()
    info = await _adapter(controller).get_controller_info(make_creds())

    assert isinstance(info, ControllerInfo)
    assert info.omadac_id == OMADAC_ID
    assert info.controller_version == "5.15.24.18"
    assert info.supports_openapi is True
    # No credential was spent.
    assert controller.auth_calls == 0


async def test_supports_openapi_is_false_below_v5_13():
    controller = FakeOmadaController()
    controller.controller_version = "5.9.31"
    info = await _adapter(controller).get_controller_info(make_creds())
    assert info.supports_openapi is False
    assert MIN_OPENAPI_VERSION == (5, 13)


async def test_controller_below_the_minimum_version_is_rejected():
    """Contract section 1's version policy: raise rather than half-work."""
    controller = FakeOmadaController()
    controller.controller_version = "4.4.6"

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).get_controller_info(make_creds())
    assert "5.0.15" in str(excinfo.value)


async def test_an_unparseable_version_does_not_block_the_integration():
    controller = FakeOmadaController()
    controller.controller_version = "some-custom-build"
    info = await _adapter(controller).get_controller_info(make_creds())
    assert info.controller_version == "some-custom-build"
    assert info.supports_openapi is False


async def test_omadac_id_is_discovered_when_not_configured():
    controller = FakeOmadaController()
    creds = make_creds(omadac_id=None)

    info = await _adapter(controller).get_controller_info(creds)
    assert info.omadac_id == OMADAC_ID
    assert "/api/info" in controller.paths()


async def test_missing_omadac_id_with_no_discovery_is_an_actionable_error():
    controller = FakeOmadaController()
    controller.info_payload = {"controllerVer": "5.15.0"}  # no omadacId
    creds = make_creds(omadac_id=None)

    with pytest.raises(OmadaInvalidControllerError) as excinfo:
        await _adapter(controller).list_sites(creds)
    assert "manually" in str(excinfo.value).lower()


async def test_a_non_omada_endpoint_is_reported_as_an_invalid_controller():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(200, text="<html>hi</html>")

    with pytest.raises(OmadaInvalidControllerError):
        await _adapter(controller).get_controller_info(make_creds())


# --- test_connection -------------------------------------------------------


async def test_test_connection_actually_authenticates():
    controller = FakeOmadaController()
    info = await _adapter(controller).test_connection(make_creds(ControllerAuthMode.OPENAPI))

    assert info.omadac_id == OMADAC_ID
    assert controller.token_count == 1


async def test_test_connection_reauthenticates_every_time():
    """Otherwise the second press would validate a cached session, not the
    credentials -- exactly when an operator most needs the truth."""
    controller = FakeOmadaController()
    adapter = _adapter(controller)
    creds = make_creds(ControllerAuthMode.OPENAPI)

    await adapter.test_connection(creds)
    await adapter.test_connection(creds)

    assert controller.auth_calls == 2


async def test_test_connection_fails_loudly_on_bad_credentials():
    from wyfy_device_gateway.omada.errors import OmadaAuthError

    controller = FakeOmadaController()
    controller.token_error_code = -44106

    with pytest.raises(OmadaAuthError):
        await _adapter(controller).test_connection(make_creds(ControllerAuthMode.OPENAPI))


async def test_test_connection_works_in_legacy_mode():
    controller = FakeOmadaController()
    info = await _adapter(controller).test_connection(make_creds(ControllerAuthMode.LEGACY))
    assert info.omadac_id == OMADAC_ID
    assert controller.login_count == 1


# --- gateway purity --------------------------------------------------------


def test_the_omada_package_imports_nothing_from_the_application_stack():
    """The gateway stays pure: no DB, no Fernet, no FastAPI, no SQLAlchemy.

    Enforced by reading the sources rather than by import side effects,
    because a conditional or function-local import would slip past a
    ``sys.modules`` check.
    """
    import pathlib

    import wyfy_device_gateway.omada as omada_pkg

    forbidden = (
        "fastapi",
        "sqlalchemy",
        "cryptography",
        "fernet",
        "psycopg",
        "asyncpg",
        "celery",
        "redis",
        "app.domains",
    )
    root = pathlib.Path(omada_pkg.__file__).parent
    offenders: list[str] = []
    for source in sorted(root.glob("*.py")):
        text = source.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if not (stripped.startswith("import ") or stripped.startswith("from ")):
                continue
            for name in forbidden:
                if name in stripped.lower():
                    offenders.append(f"{source.name}: {stripped}")
    assert offenders == [], f"gateway purity violated: {offenders}"


def test_controller_contract_has_no_heavy_imports():
    import pathlib

    import wyfy_device_gateway.controller_contract as module

    text = pathlib.Path(module.__file__).read_text()
    for name in ("fastapi", "sqlalchemy", "httpx", "pydantic"):
        assert f"import {name}" not in text


def test_contract_dataclasses_are_frozen_and_slotted():
    """Frozen + slots keeps them cheap and trivially serializable, which is
    what makes the eventual HTTP-service promotion a transport swap."""
    import dataclasses

    from wyfy_device_gateway import controller_contract as cc

    for name in (
        "ControllerCredentials",
        "ControllerInfo",
        "ControllerSite",
        "ControllerSsid",
        "ControllerDevice",
        "ControllerClient",
        "PortalAuthContext",
        "AuthorizationResult",
    ):
        cls = getattr(cc, name)
        assert dataclasses.is_dataclass(cls), name
        assert cls.__dataclass_params__.frozen, f"{name} must be frozen"
        assert hasattr(cls, "__slots__"), f"{name} must use slots"

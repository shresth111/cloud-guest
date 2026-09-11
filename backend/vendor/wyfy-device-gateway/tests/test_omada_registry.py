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


# --- controller identity on a cloud-managed controller ---------------------
#
# Everything in this block is a regression test for a defect that met real
# hardware on 2026-09-11 and that 5,135 passing tests could not see, because
# the fake controller answered the shape we had written rather than the shape
# a controller sends.
#
# TP-Link's cloud edge (https://aps1-api-omada-controller.tplinkcloud.com)
# 404s the unscoped ``/api/info`` -- one address there fronts many
# controllers -- so `_controller_info` raised OmadaUnsupportedApiError and
# `test_connection` refused a controller whose hotspot login worked perfectly
# on the very same host, seconds earlier, by curl.


def _cloud(controller: FakeOmadaController) -> FakeOmadaController:
    """The fake, switched to the cloud edge's behaviour."""
    controller.serves_unscoped_info = False
    return controller


async def test_a_cloud_controller_is_identified_through_the_scoped_path():
    controller = _cloud(FakeOmadaController())

    info = await _adapter(controller).get_controller_info(make_creds())

    assert info.omadac_id == OMADAC_ID
    assert info.controller_version == "5.15.24.18"
    # The unscoped path was tried and 404'd; the scoped one answered.
    assert controller.paths() == ["/api/info", f"/{OMADAC_ID}/api/info"]
    assert controller.auth_calls == 0


async def test_test_connection_accepts_a_cloud_controller():
    """The defect, stated as a test: before the fallback this raised
    OmadaUnsupportedApiError while the operator login below succeeded."""
    controller = _cloud(FakeOmadaController())

    info = await _adapter(controller).test_connection(
        make_creds(ControllerAuthMode.LEGACY)
    )

    assert info.omadac_id == OMADAC_ID
    assert controller.login_count == 1


async def test_a_cloud_controller_with_no_omadac_id_names_the_field_to_fill_in():
    """There is nothing to scope the request with, so this genuinely cannot
    work -- but "does not support the requested operation" sent operators to
    check the wrong thing. The message has to name the Omada ID."""
    controller = _cloud(FakeOmadaController())

    with pytest.raises(OmadaInvalidControllerError) as excinfo:
        await _adapter(controller).get_controller_info(make_creds(omadac_id=None))

    message = str(excinfo.value)
    assert "Omada ID" in message
    assert "/api/info" in message


async def test_a_wrong_omadac_id_is_reported_as_a_wrong_omadac_id():
    """VERIFIED on hardware: the scoped path answers -7131 for an id the host
    does not hold, on the cloud edge and on a direct controller alike. The
    generic "does not look like an Omada controller" would point at the URL,
    which is the one field that is right."""
    controller = _cloud(FakeOmadaController())

    with pytest.raises(OmadaInvalidControllerError) as excinfo:
        await _adapter(controller).get_controller_info(make_creds(omadac_id="0" * 32))

    assert "controller ID" in str(excinfo.value)
    assert excinfo.value.provider_code == -7131


async def test_a_direct_controller_does_not_pay_for_the_fallback():
    """The unscoped path still answers first everywhere it ever did, so no
    controller that works today makes an extra round trip."""
    controller = FakeOmadaController()

    await _adapter(controller).get_controller_info(make_creds())

    assert controller.paths() == ["/api/info"]


# --- model is not the type enum -------------------------------------------


async def test_model_is_not_reported_from_the_type_enum():
    """Real controllers send ``type`` as an integer and no ``model`` at all
    (1 on Omada Software Controller 5.15.24.19, 20 on a cloud-managed
    6.3.0.100). Reading ``type`` as the model showed operators the string
    "1" as their controller model after Test Connection."""
    controller = FakeOmadaController()

    info = await _adapter(controller).get_controller_info(make_creds())

    assert info.model is None


async def test_a_real_model_field_is_used_and_no_longer_shadowed():
    """``type`` was checked first, so a controller that did send a ``model``
    would have had it hidden behind the enum."""
    controller = FakeOmadaController()
    controller.info_payload = {
        "controllerVer": "5.15.24.18",
        "omadacId": OMADAC_ID,
        "type": 1,
        "model": "OC200",
    }

    info = await _adapter(controller).get_controller_info(make_creds())

    assert info.model == "OC200"


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


async def test_openapi_test_connection_also_proves_a_stored_operator_login():
    """The app and the operator account are two credentials; guest sign-in
    uses the second. A test that proved only the first would go green over
    a mistyped operator password."""
    from omada_support import OPERATOR_PASSWORD, OPERATOR_USERNAME

    controller = FakeOmadaController()
    info = await _adapter(controller).test_connection(
        make_creds(
            ControllerAuthMode.OPENAPI,
            username=OPERATOR_USERNAME,
            password=OPERATOR_PASSWORD,
        )
    )

    assert info.omadac_id == OMADAC_ID
    assert controller.token_count == 1
    assert controller.login_count == 1


async def test_openapi_test_connection_names_the_operator_account_when_it_is_refused():
    from omada_support import OPERATOR_USERNAME

    from wyfy_device_gateway.omada.errors import OmadaAuthError

    controller = FakeOmadaController()
    with pytest.raises(OmadaAuthError, match="hotspot operator account"):
        await _adapter(controller).test_connection(
            make_creds(
                ControllerAuthMode.OPENAPI,
                username=OPERATOR_USERNAME,
                password="not-the-operator-password",
            )
        )
    # The app itself was fine: its token was issued before the operator
    # login was tried.
    assert controller.token_count == 1


async def test_openapi_test_connection_without_an_operator_login_tries_none():
    """No operator pair stored means nothing to prove -- and no operator
    login attempt that would read as a failure."""
    controller = FakeOmadaController()
    await _adapter(controller).test_connection(make_creds(ControllerAuthMode.OPENAPI))

    assert controller.login_count == 0


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

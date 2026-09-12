"""``POST /network-integrations/platform/test-connection`` -- the org-less probe.

The Master console's "Add customer" wizard onboards an Omada controller in
the same flow that creates the customer, so at the device step there is
usually no organization yet. The customer probe (``POST /test-connection``)
needs one. This is the GLOBAL-scoped twin, plus what the wizard needs to fill
the controller form in for the operator: a suggested certificate trust mode
and, with Open API credentials, the controller's sites and SSIDs.

Three layers, each proving something the others cannot:

* **Permission** -- the real ``RequirePermission`` dependency on the real
  route, evaluated by a real ``AccessValidator`` over ``test_rbac``'s fake
  repository, over HTTP. An Organization Owner holds
  ``network_integrations.create`` at ORGANIZATION scope; that must be a 403
  here, and the controller must never be dialled.
* **Service + route shaping** -- the real service over a certificate-aware
  fake provider, so the trust-mode outcomes are the gateway's semantics
  (strict refuses an untrusted chain, pinned refuses a different
  fingerprint) rather than whatever a fake was told to return.
* **Wire** -- the real ``OmadaProvider`` and the real gateway adapter over
  ``httpx.MockTransport``, answering with bodies shaped exactly as TP-Link's
  Open API spec (OpenAPI 3.0.1, ``/v3/api-docs``) defines them. That is the
  only layer that can show the site and SSID parsing is right.

Helpers are imported from ``test_network_integration`` rather than copied.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.common.exceptions import register_exception_handlers
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.network_integration.constants import (
    ControllerTlsMode,
    ErrorCode,
    NetworkIntegrationAuditAction,
)
from app.domains.network_integration.dependencies import (
    get_network_integration_service,
)
from app.domains.network_integration.exceptions import (
    NetworkIntegrationUrlRejectedError,
    ProviderAuthFailedError,
    ProviderConnectionFailedError,
    ProviderTlsPinMismatchError,
    ProviderTlsUntrustedError,
    ProviderUnsupportedApiError,
)
from app.domains.network_integration.providers.base import (
    ProviderControllerInfo,
    ProviderTlsObservation,
)
from app.domains.network_integration.router import _integration_response
from app.domains.network_integration.router import router as integration_router
from app.domains.network_integration.service import NetworkIntegrationService
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_current_user
from app.domains.rbac.enums import ScopeType

from .test_network_integration import (
    _PIN,
    CONTROLLER_URL,
    FakeAuditWriter,
    FakeProvider,
    FakeRepository,
    _integration,
    _resolves_private,
    _resolves_public,
    _service,
)
from .test_rbac import FakeRBACRepository, assign_role, make_permission, make_role

PROBE_PATH = "/api/v1/network-integrations/platform/test-connection"
SECRET = "TOP-SECRET-client-secret-value"
OPERATOR_PASSWORD = "TOP-SECRET-operator-password"

# ============================================================================
# Fakes
# ============================================================================


@dataclass
class _ExplodingRepository:
    """A repository any use of which fails the test.

    Stronger than asserting an in-memory store stayed empty: the probe must
    not *read* a row either, because there is no organization to scope a
    read by. Any attribute access is the failure.
    """

    touched: list[str] = field(default_factory=list)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        self.touched.append(name)
        raise AssertionError(f"the draft probe touched repository.{name}")


@dataclass
class _CertificateAwareProvider(FakeProvider):
    """A fake that enforces trust the way the gateway does.

    ``strict`` refuses a chain that is not publicly trusted
    (``OMADA_TLS_UNTRUSTED``); ``pinned`` refuses any certificate but the
    pinned one (``OMADA_TLS_PIN_MISMATCH``). So "pinned with the matching
    fingerprint succeeds" is a consequence of the fingerprint, not of the
    fake having been told to succeed.
    """

    def _enforce_trust(self, config: Any) -> None:
        observed = self.tls_observation
        assert observed is not None
        mode = config.tls_mode
        if mode == ControllerTlsMode.STRICT.value and not observed.chain_trusted:
            raise ProviderTlsUntrustedError()
        if (
            mode == ControllerTlsMode.PINNED.value
            and config.tls_pinned_sha256 != observed.fingerprint_sha256
        ):
            raise ProviderTlsPinMismatchError()

    async def test_connection(self, config) -> ProviderControllerInfo:
        self._enforce_trust(config)
        return await super().test_connection(config)

    async def get_controller_info(self, config) -> ProviderControllerInfo:
        self._enforce_trust(config)
        return await super().get_controller_info(config)

    async def inspect_tls(self, config) -> ProviderTlsObservation:
        observation = await super().inspect_tls(config)
        pin = config.tls_pinned_sha256
        return ProviderTlsObservation(
            fingerprint_sha256=observation.fingerprint_sha256,
            chain_trusted=observation.chain_trusted,
            matches_pin=None if pin is None else pin == observation.fingerprint_sha256,
            subject=observation.subject,
            issuer=observation.issuer,
            not_valid_after=observation.not_valid_after,
        )


def _self_signed() -> ProviderTlsObservation:
    """What a self-hosted Omada Software Controller presents (runbook §3)."""
    return ProviderTlsObservation(
        fingerprint_sha256=_PIN,
        chain_trusted=False,
        subject="CN=localhost",
        issuer="CN=localhost",
    )


def _publicly_trusted() -> ProviderTlsObservation:
    return ProviderTlsObservation(
        fingerprint_sha256="b" * 64,
        chain_trusted=True,
        subject="CN=controller.example.com",
        issuer="CN=R11,O=Let's Encrypt,C=US",
    )


# ============================================================================
# HTTP wiring
# ============================================================================

_GLOBAL_ACTOR = AuthUser(id=str(uuid.uuid4()), email="platform@wyfy.example")


class _PermitAll:
    async def check(self, *_args: object, **_kwargs: object) -> None:
        return None


def _app(
    service: Any,
    *,
    validator: Any | None = None,
    actor: AuthUser = _GLOBAL_ACTOR,
) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(integration_router, prefix="/api/v1")
    app.dependency_overrides[get_network_integration_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_access_validator] = lambda: validator or _PermitAll()
    # RequirePermission only consults the session to resolve a router or
    # location named by the request; this route names neither.
    app.dependency_overrides[get_db_session] = lambda: None
    return app


async def _post(
    app: FastAPI, body: dict[str, Any], headers: dict[str, str] | None = None
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(PROBE_PATH, json=body, headers=headers or {})


def _legacy_body(**overrides: object) -> dict[str, Any]:
    body: dict[str, Any] = {
        "base_url": CONTROLLER_URL,
        "auth_mode": "legacy",
        "username": "wyfyportal",
        "password": OPERATOR_PASSWORD,
    }
    body.update(overrides)
    return body


def _openapi_body(**overrides: object) -> dict[str, Any]:
    body: dict[str, Any] = {
        "base_url": CONTROLLER_URL,
        "auth_mode": "openapi",
        "client_id": "cid",
        "client_secret": SECRET,
    }
    body.update(overrides)
    return body


# ============================================================================
# 1. Permission: GLOBAL only
# ============================================================================


class TestTheProbeIsGlobalScoped:
    def test_the_route_declares_create_at_global_scope(self) -> None:
        """Structural, and deliberately about *this* route: the permission
        key and the scope both live in the dependency's closure."""
        route = next(
            r
            for r in integration_router.routes
            if r.path == "/network-integrations/platform/test-connection"
        )
        assert route.methods == {"POST"}
        captured: list[object] = []
        for dep in route.dependant.dependencies:
            captured.extend(cell.cell_contents for cell in (dep.call.__closure__ or ()))
        assert ScopeType.GLOBAL in captured
        assert "network_integrations.create" in captured

    async def _validator_granting(self, scope: ScopeType, **assignment: Any):
        repo = FakeRBACRepository()
        permission = await make_permission(repo, "network_integrations", "create")
        role = await make_role(repo, f"Holder {scope.value}", scope_type=scope)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        await assign_role(
            repo, user_id=user_id, role=role, scope_type=scope, **assignment
        )
        return AccessValidator(repo), AuthUser(
            id=str(user_id), email="someone@example.test"
        )

    async def test_an_organization_scoped_holder_is_refused_with_403(self) -> None:
        """The Organization Owner shape: the permission, at ORGANIZATION
        scope, with their own organization in the header. Without the
        explicit GLOBAL on the route, scope inference would resolve
        ORGANIZATION from that header and let them in."""
        org = uuid.uuid4()
        validator, actor = await self._validator_granting(
            ScopeType.ORGANIZATION, organization_id=org
        )
        provider = FakeProvider()
        service = _service(provider=provider)
        response = await _post(
            _app(service, validator=validator, actor=actor),
            _legacy_body(),
            headers={"X-Organization-Id": str(org)},
        )
        assert response.status_code == 403, response.text
        # Refused before anything was dialled.
        assert provider.calls == []
        assert provider.identity_configs == []

    async def test_a_global_holder_gets_an_answer(self) -> None:
        validator, actor = await self._validator_granting(ScopeType.GLOBAL)
        response = await _post(
            _app(_service(), validator=validator, actor=actor), _legacy_body()
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["ok"] is True

    def test_the_platform_route_is_registered_before_the_by_id_routes(self) -> None:
        """``/platform/test-connection`` must never be swallowed by a
        parameterised ``/{integration_id}`` route registered ahead of it."""
        paths = [r.path for r in integration_router.routes]
        probe = paths.index("/network-integrations/platform/test-connection")
        by_id = [i for i, p in enumerate(paths) if "{integration_id}" in p]
        first_customer_by_id = min(i for i in by_id if "/platform/" not in paths[i])
        assert probe < first_customer_by_id


# ============================================================================
# 2. Certificate trust, and what the wizard is told to do about it
# ============================================================================


class TestSuggestedTrustMode:
    async def test_a_self_signed_controller_fails_with_its_fingerprint_and_pinned(
        self,
    ) -> None:
        provider = _CertificateAwareProvider(tls_observation=_self_signed())
        response = await _post(_app(_service(provider=provider)), _legacy_body())
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["ok"] is False
        assert data["error_code"] == ErrorCode.TLS_UNTRUSTED.value
        assert "certificate" in data["message"].lower()
        # The whole point: the value to pin arrives with the failure.
        assert data["tls_fingerprint_sha256"] == _PIN
        assert data["tls_chain_trusted"] is False
        assert data["tls_certificate_subject"] == "CN=localhost"
        assert data["tls_certificate_issuer"] == "CN=localhost"
        assert data["suggested_tls_mode"] == "pinned"

    async def test_a_publicly_trusted_controller_suggests_strict(self) -> None:
        provider = _CertificateAwareProvider(tls_observation=_publicly_trusted())
        response = await _post(_app(_service(provider=provider)), _legacy_body())
        data = response.json()["data"]
        assert data["ok"] is True
        assert data["tls_chain_trusted"] is True
        assert data["suggested_tls_mode"] == "strict"

    async def test_pinning_the_observed_fingerprint_succeeds(self) -> None:
        """The one-click "trust this certificate" round trip: probe, read the
        fingerprint, probe again pinned to it."""
        provider = _CertificateAwareProvider(tls_observation=_self_signed())
        app = _app(_service(provider=provider))
        first = (await _post(app, _legacy_body())).json()["data"]
        second = (
            await _post(
                app,
                _legacy_body(
                    tls_mode="pinned",
                    tls_pinned_sha256=first["tls_fingerprint_sha256"],
                ),
            )
        ).json()["data"]
        assert second["ok"] is True
        assert second["error_code"] is None
        assert second["credentials_checked"] is True
        assert second["tls_matches_pin"] is True
        # Still says the chain is not public -- pinning is the right answer.
        assert second["suggested_tls_mode"] == "pinned"
        assert second["controller_id"] == "abc123"
        assert second["controller_version"] == "5.14.20"

    async def test_pinning_a_different_fingerprint_is_a_pin_mismatch(self) -> None:
        provider = _CertificateAwareProvider(tls_observation=_self_signed())
        response = await _post(
            _app(_service(provider=provider)),
            _legacy_body(tls_mode="pinned", tls_pinned_sha256="c" * 64),
        )
        data = response.json()["data"]
        assert data["ok"] is False
        assert data["error_code"] == ErrorCode.TLS_PIN_MISMATCH.value
        assert data["tls_matches_pin"] is False
        assert data["tls_fingerprint_sha256"] == _PIN

    async def test_no_observation_means_no_suggestion(self) -> None:
        """Unreachable: there is no certificate to reason about, and
        guessing a mode would be a trust decision made for the operator."""
        provider = FakeProvider(
            tls_observation=None,
            raise_on={"test_connection": ProviderConnectionFailedError()},
        )
        response = await _post(_app(_service(provider=provider)), _legacy_body())
        data = response.json()["data"]
        assert data["ok"] is False
        assert data["error_code"] == ErrorCode.CONNECTION_FAILED.value
        assert data["tls_fingerprint_sha256"] is None
        assert data["suggested_tls_mode"] is None

    async def test_an_auth_failure_keeps_its_own_code(self) -> None:
        provider = FakeProvider(raise_on={"test_connection": ProviderAuthFailedError()})
        data = (await _post(_app(_service(provider=provider)), _legacy_body())).json()[
            "data"
        ]
        assert data["ok"] is False
        assert data["error_code"] == ErrorCode.AUTH_FAILED.value


class TestAddressOnly:
    """The wizard probes as soon as the address is typed, before credentials."""

    async def test_no_credentials_probes_identity_and_certificate_only(self) -> None:
        provider = FakeProvider(tls_observation=_publicly_trusted())
        data = (
            await _post(
                _app(_service(provider=provider)),
                {"base_url": CONTROLLER_URL, "auth_mode": "legacy"},
            )
        ).json()["data"]
        assert data["ok"] is True
        # `ok` here must not be read as "the password works".
        assert data["credentials_checked"] is False
        assert data["controller_id"] == "abc123"
        assert data["tls_fingerprint_sha256"] == "b" * 64
        assert data["suggested_tls_mode"] == "strict"
        assert "get_controller_info" in provider.calls
        assert "test_connection" not in provider.calls
        assert "list_sites" not in provider.calls

    async def test_no_credentials_on_a_self_signed_controller_still_shows_the_pin(
        self,
    ) -> None:
        provider = _CertificateAwareProvider(tls_observation=_self_signed())
        data = (
            await _post(
                _app(_service(provider=provider)),
                {"base_url": CONTROLLER_URL, "auth_mode": "openapi"},
            )
        ).json()["data"]
        assert data["ok"] is False
        assert data["error_code"] == ErrorCode.TLS_UNTRUSTED.value
        assert data["credentials_checked"] is False
        assert data["tls_fingerprint_sha256"] == _PIN
        assert data["suggested_tls_mode"] == "pinned"

    async def test_half_a_credential_is_still_refused(self) -> None:
        provider = FakeProvider()
        response = await _post(
            _app(_service(provider=provider)),
            {"base_url": CONTROLLER_URL, "auth_mode": "legacy", "username": "op"},
        )
        assert response.status_code == 422
        assert provider.calls == []


# ============================================================================
# 3. Inventory: Open API lists, a hotspot operator cannot
# ============================================================================


class TestInventory:
    async def test_hotspot_operator_credentials_return_empty_lists_and_a_flag(
        self,
    ) -> None:
        """Runbook §6: that account cannot list sites or SSIDs. Empty lists
        plus a flag, never an error -- and never a request that the
        controller would refuse as though the password were wrong."""
        provider = FakeProvider()
        data = (await _post(_app(_service(provider=provider)), _legacy_body())).json()[
            "data"
        ]
        assert data["ok"] is True
        assert data["inventory_requires_openapi"] is True
        assert data["inventory_available"] is False
        assert data["inventory_error_code"] is None
        assert data["sites"] == []
        assert data["ssids"] == []
        assert data["ssids_site_id"] is None
        assert "list_sites" not in provider.calls
        assert "list_ssids" not in provider.calls

    async def test_the_flag_is_set_even_when_the_operator_probe_fails(self) -> None:
        provider = FakeProvider(raise_on={"test_connection": ProviderAuthFailedError()})
        data = (await _post(_app(_service(provider=provider)), _legacy_body())).json()[
            "data"
        ]
        assert data["inventory_requires_openapi"] is True
        assert data["sites"] == []

    async def test_open_api_credentials_list_sites_and_the_only_sites_ssids(
        self,
    ) -> None:
        provider = FakeProvider()
        data = (await _post(_app(_service(provider=provider)), _openapi_body())).json()[
            "data"
        ]
        assert data["ok"] is True
        assert data["inventory_requires_openapi"] is False
        assert data["inventory_available"] is True
        assert [(s["site_id"], s["name"]) for s in data["sites"]] == [
            ("site-1", "Default")
        ]
        assert data["ssids_site_id"] == "site-1"
        assert [(s["ssid_id"], s["name"]) for s in data["ssids"]] == [
            ("ssid-1", "Guest WiFi")
        ]

    async def test_an_inventory_failure_does_not_fail_the_probe(self) -> None:
        """Sign-in worked; the controller then refused a listing. The
        connection is fine and the wizard must say so."""
        provider = FakeProvider(
            raise_on={"list_sites": ProviderUnsupportedApiError("nope")}
        )
        data = (await _post(_app(_service(provider=provider)), _openapi_body())).json()[
            "data"
        ]
        assert data["ok"] is True
        assert data["error_code"] is None
        assert data["inventory_available"] is False
        assert data["inventory_error_code"] == ErrorCode.API_UNSUPPORTED.value
        assert data["inventory_message"] == "nope"
        assert data["sites"] == []

    async def test_an_unknown_site_id_is_reported_and_the_sites_still_listed(
        self,
    ) -> None:
        provider = FakeProvider()
        data = (
            await _post(
                _app(_service(provider=provider)), _openapi_body(site_id="nope")
            )
        ).json()["data"]
        assert data["ok"] is True
        assert data["inventory_error_code"] == ErrorCode.SITE_NOT_FOUND.value
        assert [s["site_id"] for s in data["sites"]] == ["site-1"]
        assert data["ssids"] == []
        assert "list_ssids" not in provider.calls


# ============================================================================
# 4. Nothing persisted, nothing echoed, same outbound rules
# ============================================================================


class TestNothingPersistedAndNothingLeaked:
    def _service_over(self, repository: Any, audit: FakeAuditWriter, provider=None):
        return NetworkIntegrationService(
            repository,
            audit_writer=audit,
            provider_resolver=lambda _kind: provider or FakeProvider(),
            url_resolver=_resolves_public,
        )

    async def test_no_repository_access_at_all_on_success_or_failure(self) -> None:
        repository = _ExplodingRepository()
        audit = FakeAuditWriter()
        ok = self._service_over(repository, audit)
        outcome = await ok.probe_controller_draft(
            actor_user_id=uuid.uuid4(),
            provider="omada",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            client_id="cid",
            client_secret=SECRET,
        )
        assert outcome.error is None
        failing = self._service_over(
            repository,
            audit,
            FakeProvider(raise_on={"test_connection": ProviderTlsUntrustedError()}),
        )
        outcome = await failing.probe_controller_draft(
            actor_user_id=uuid.uuid4(),
            provider="omada",
            base_url=CONTROLLER_URL,
            auth_mode="legacy",
            username="op",
            password=OPERATOR_PASSWORD,
        )
        assert outcome.error is not None
        assert repository.touched == []

    async def test_no_integration_or_event_rows_only_an_org_less_audit_entry(
        self,
    ) -> None:
        repo = FakeRepository()
        audit = FakeAuditWriter()
        service = _service(repo, audit=audit)
        response = await _post(_app(service), _openapi_body())
        assert response.status_code == 200
        assert repo.integrations == {}
        assert repo.events == []
        assert repo.authorizations == []
        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["action"] == NetworkIntegrationAuditAction.TEST_CONNECTION.value
        assert entry["organization_id"] is None
        assert entry["entity_id"] is None
        assert entry["event_metadata"]["platform_action"] is True

    async def test_credentials_are_never_echoed_or_audited(self) -> None:
        audit = FakeAuditWriter()
        response = await _post(
            _app(_service(audit=audit)),
            _openapi_body(username="op", password=OPERATOR_PASSWORD),
        )
        assert SECRET not in response.text
        assert OPERATOR_PASSWORD not in response.text
        assert "client_secret" not in response.json()["data"]
        assert SECRET not in str(audit.entries)
        assert OPERATOR_PASSWORD not in str(audit.entries)

    async def test_an_address_resolving_to_a_private_range_is_refused_undialled(
        self,
    ) -> None:
        provider = FakeProvider()
        service = NetworkIntegrationService(
            FakeRepository(),
            audit_writer=FakeAuditWriter(),
            provider_resolver=lambda _kind: provider,
            url_resolver=_resolves_private,
        )
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.probe_controller_draft(
                actor_user_id=None,
                provider="omada",
                base_url=CONTROLLER_URL,
                auth_mode="legacy",
                username="op",
                password="pw",
            )
        assert provider.calls == []

    async def test_a_port_outside_the_allowlist_is_refused_over_http(self) -> None:
        provider = FakeProvider()
        response = await _post(
            _app(_service(provider=provider)),
            _legacy_body(base_url="https://controller.example.com:1234"),
        )
        assert response.status_code == 422
        assert provider.calls == []

    async def test_a_cloud_controllers_omada_id_is_forwarded(self) -> None:
        provider = FakeProvider()
        await _post(
            _app(_service(provider=provider)),
            _legacy_body(controller_id="e1b99b469a8c0cfeee4466cfc1018c96"),
        )
        assert provider.identity_configs[0].controller_id == (
            "e1b99b469a8c0cfeee4466cfc1018c96"
        )


# ============================================================================
# 5. On the wire: the real provider and gateway, spec-shaped controller bodies
# ============================================================================

_OMADAC_ID = "e1b99b469a8c0cfeee4466cfc1018c96"
_ACCESS_TOKEN = "AT-probe-access-token-0123456789"
_SITE_A = "6634a9c2b7e8d1234567890a"
_SITE_B = "6634a9c2b7e8d1234567890b"
_WLAN = "6634a9c2b7e8d12345678aaa"


def _envelope(result: Any) -> dict[str, Any]:
    return {"errorCode": 0, "msg": "Success.", "result": result}


def _grid(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """``GridVO*``: ``{totalRows, currentPage, currentSize, data}``."""
    return {
        "totalRows": len(rows),
        "currentPage": 1,
        "currentSize": len(rows),
        "data": rows,
    }


def _site(site_id: str, name: str, *, primary: bool) -> dict[str, Any]:
    """``SiteSummaryInfo``. No deviceCount/clientCount -- the spec has none."""
    return {
        "siteId": site_id,
        "name": name,
        "tagIds": [],
        "region": "India",
        "timeZone": "Asia/Kolkata",
        "scenario": "Hotel",
        "type": 0,
        "supportES": True,
        "supportL2": True,
        "primary": primary,
    }


def _wlan_group(site_id: str) -> dict[str, Any]:
    """``WlanGroupOpenApiVO``."""
    return {
        "wlanId": _WLAN,
        "id": _WLAN,
        "name": "Default",
        "primary": True,
        "clone": False,
        "site": site_id,
        "resource": 0,
    }


def _ssid(ssid_id: str, name: str, *, guest: bool) -> dict[str, Any]:
    """``SsidOpenApiVO``. No portalEnable -- the spec has none."""
    return {
        "ssidId": ssid_id,
        "id": ssid_id,
        "name": name,
        "band": 3,
        "guestNetEnable": guest,
        "security": 0 if guest else 3,
        "broadcast": True,
        "vlanEnable": False,
    }


@dataclass
class _SpecController:
    """A controller answering the four calls the probe makes, as specified.

    ``GET /api/info`` is the unauthenticated identity call (shape observed on
    5.15.24.19). The token call is TP-Link doc 109315's client-credentials
    grant. The three inventory paths and their response schemas --
    ``OperationResponseGridVOSiteSummaryInfo``,
    ``OperationResponseListWlanGroupOpenApiVO`` (a bare array, not a grid)
    and ``OperationResponseGridVOSsidOpenApiVO`` -- are TP-Link's OpenAPI
    3.0.1 spec, operations ``getSiteList``, ``getWlanGroupList`` and
    ``getSsidList``. Every field in the fixtures above is a property of the
    corresponding spec schema.
    """

    requests: list[httpx.Request] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/info":
            return httpx.Response(
                200,
                json=_envelope(
                    {
                        "controllerVer": "5.15.24.19",
                        "apiVer": "3",
                        "configured": True,
                        "type": 1,
                        "supportApp": True,
                        "omadacId": _OMADAC_ID,
                    }
                ),
            )
        if path == "/openapi/authorize/token":
            return httpx.Response(
                200,
                json=_envelope(
                    {
                        "accessToken": _ACCESS_TOKEN,
                        "tokenType": "bearer",
                        "expiresIn": 7200,
                        "refreshToken": "RT-probe-refresh-token",
                    }
                ),
            )
        assert request.headers.get("Authorization") == f"AccessToken={_ACCESS_TOKEN}"
        if path == f"/openapi/v1/{_OMADAC_ID}/sites":
            return httpx.Response(
                200,
                json=_envelope(
                    _grid(
                        [
                            _site(_SITE_A, "Lobby", primary=True),
                            _site(_SITE_B, "Annex", primary=False),
                        ]
                    )
                ),
            )
        wlans = f"/openapi/v1/{_OMADAC_ID}/sites/{_SITE_A}/wireless-network/wlans"
        if path == wlans:
            return httpx.Response(200, json=_envelope([_wlan_group(_SITE_A)]))
        if path == f"{wlans}/{_WLAN}/ssids":
            return httpx.Response(
                200,
                json=_envelope(
                    _grid(
                        [
                            _ssid("ssid-staff", "Staff", guest=False),
                            _ssid("ssid-guest", "Hotel Guest", guest=True),
                        ]
                    )
                ),
            )
        return httpx.Response(404, json={"errorCode": -1, "msg": "not found"})


@pytest.fixture
def spec_controller(monkeypatch: pytest.MonkeyPatch) -> _SpecController:
    """Install the real gateway adapter over a ``MockTransport``.

    Two seams, both the ones the code itself names: the provider's cached
    adapter (``providers/omada.py``'s ``_ADAPTER_CACHE``) and the provider's
    pre-request URL re-validation, whose resolver would otherwise do a real
    DNS lookup. ``inspect_tls`` is stubbed on the adapter instance because it
    sits below HTTP -- the gateway's own docstring calls that the honest
    seam, since a ``MockTransport`` has no certificate.
    """
    pytest.importorskip("wyfy_device_gateway.omada.adapter")
    from wyfy_device_gateway.controller_contract import ControllerTlsObservation
    from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter

    from app.domains.network_integration.providers import omada as omada_module
    from app.domains.network_integration.validators import validate_controller_url

    controller = _SpecController()

    async def _no_sleep(_seconds: float) -> None:
        return None

    adapter = OmadaControllerAdapter(
        transport=httpx.MockTransport(controller.handle), sleep=_no_sleep
    )

    async def _inspect_tls(_creds: Any) -> ControllerTlsObservation:
        return ControllerTlsObservation(
            fingerprint_sha256="d" * 64,
            certificate_der=None,
            chain_trusted=True,
            matches_pin=None,
        )

    monkeypatch.setattr(adapter, "inspect_tls", _inspect_tls)
    monkeypatch.setitem(omada_module._ADAPTER_CACHE, "adapter", adapter)

    async def _validate(raw: str, **kwargs: Any):
        return await validate_controller_url(raw, resolver=_resolves_public)

    monkeypatch.setattr(omada_module, "validate_controller_url", _validate)
    return controller


def _real_provider_service(audit: FakeAuditWriter | None = None):
    from app.domains.network_integration.providers.omada import OmadaProvider

    return NetworkIntegrationService(
        FakeRepository(),
        audit_writer=audit or FakeAuditWriter(),
        provider_resolver=lambda _kind: OmadaProvider(),
        url_resolver=_resolves_public,
    )


class TestAgainstASpecShapedController:
    async def test_sites_are_listed_and_ssids_wait_for_a_site_when_there_are_two(
        self, spec_controller: _SpecController
    ) -> None:
        response = await _post(_app(_real_provider_service()), _openapi_body())
        data = response.json()["data"]
        assert data["ok"] is True, data
        assert data["controller_id"] == _OMADAC_ID
        assert data["controller_version"] == "5.15.24.19"
        assert data["supports_openapi"] is True
        # ``type`` is an unpublished enum, not a model (see the adapter).
        assert data["model"] is None
        assert data["suggested_tls_mode"] == "strict"
        assert data["inventory_available"] is True
        assert [(s["site_id"], s["name"]) for s in data["sites"]] == [
            (_SITE_A, "Lobby"),
            (_SITE_B, "Annex"),
        ]
        # Two sites and none chosen: listing SSIDs would be a guess.
        assert data["ssids_site_id"] is None
        assert data["ssids"] == []
        sites_call = next(
            r for r in spec_controller.requests if r.url.path.endswith("/sites")
        )
        # `page` and `pageSize` are required by the spec (getSiteList).
        assert sites_call.url.params["page"] == "1"
        assert "pageSize" in sites_call.url.params

    async def test_the_chosen_sites_ssids_are_listed(
        self, spec_controller: _SpecController
    ) -> None:
        data = (
            await _post(_app(_real_provider_service()), _openapi_body(site_id=_SITE_A))
        ).json()["data"]
        assert data["ssids_site_id"] == _SITE_A
        assert [(s["ssid_id"], s["name"]) for s in data["ssids"]] == [
            ("ssid-staff", "Staff"),
            ("ssid-guest", "Hotel Guest"),
        ]
        # The spec has no portal flag on an SSID; absence is not "off".
        assert {s["portal_enabled"] for s in data["ssids"]} == {None}

    async def test_the_address_alone_discovers_the_omada_id_without_signing_in(
        self, spec_controller: _SpecController
    ) -> None:
        data = (
            await _post(
                _app(_real_provider_service()),
                {"base_url": CONTROLLER_URL, "auth_mode": "openapi"},
            )
        ).json()["data"]
        assert data["ok"] is True, data
        assert data["credentials_checked"] is False
        assert data["controller_id"] == _OMADAC_ID
        assert data["controller_version"] == "5.15.24.19"
        assert [r.url.path for r in spec_controller.requests] == ["/api/info"]

    async def test_the_client_secret_goes_to_the_token_call_and_nowhere_else(
        self, spec_controller: _SpecController
    ) -> None:
        audit = FakeAuditWriter()
        response = await _post(
            _app(_real_provider_service(audit)), _openapi_body(site_id=_SITE_A)
        )
        assert SECRET not in response.text
        assert SECRET not in str(audit.entries)
        carrying = [
            r.url.path for r in spec_controller.requests if SECRET.encode() in r.content
        ]
        assert carrying == ["/openapi/authorize/token"]
        token_call = next(
            r
            for r in spec_controller.requests
            if r.url.path == "/openapi/authorize/token"
        )
        assert json.loads(token_call.content)["omadacId"] == _OMADAC_ID


# ============================================================================
# 6. NetworkIntegrationResponse.router_id
# ============================================================================


class TestTheResponseCarriesTheFleetRouterId:
    """The frontend matched an integration to its fleet router by parsing
    ``routerId=`` out of ``portal_url_host_and_query``. The column exists;
    now the response says it."""

    def test_the_router_id_is_returned(self) -> None:
        router_id = uuid.uuid4()
        payload = _integration_response(
            _integration(location_id=uuid.uuid4(), router_id=router_id)
        )
        assert payload.router_id == router_id
        assert payload.model_dump(mode="json")["router_id"] == str(router_id)
        # And it is the same id the portal URL already carried.
        assert f"routerId={router_id}" in (payload.portal_url_host_and_query or "")

    def test_a_fleetless_integration_says_none(self) -> None:
        payload = _integration_response(_integration(router_id=None))
        assert payload.router_id is None
        assert payload.model_dump(mode="json")["router_id"] is None

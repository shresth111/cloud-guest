"""Unit tests for the Network Integration domain.

Covers the shared contract's §9 list: authentication in both modes,
connection testing, invalid credentials, site loading, **tenant
isolation**, client lookup, guest authorize, guest deauthorize (which
Omada cannot do -- CR-001), session expiry, timeout, retry/backoff,
malformed controller URLs, **SSRF rejection**, permission checks,
integration CRUD, and an end-to-end captive-portal authorize flow.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_mac_authorization.py``); ``asyncio_mode = "auto"`` runs
async tests directly.

## No test here requires an Omada controller, or the gateway package

Every provider interaction goes through a hand-rolled fake satisfying
``providers.base.NetworkProvider``. That is not merely convenient -- it is
the property that makes this domain's test suite independent of another
repository's build state. The gateway's ``wyfy_device_gateway.omada``
package is imported lazily and only on a real outbound call (see
``providers/omada.py``), so these tests pass whether it is installed or
not.

The consequence, stated plainly rather than implied: **these tests prove
this domain's logic, not that Omada works.** Nothing here has contacted a
controller. What is verified against a real device is nothing; what is
verified against the documented contract is the error-code translation and
the field mapping.

## Two tests here are load-bearing security tests, not coverage

``TestTenantIsolation`` and ``TestSsrfRejection``. The first pins the
defect class this codebase has already leaked across tenants fourteen
times -- permission check on the header org, read on the path id. The
second pins the fact that ``base_url`` is user-supplied input that reaches
a server-side HTTP client carrying a tenant's controller credentials. If
either starts failing, the correct response is to stop, not to adjust the
assertion.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.network_integration.constants import (
    MAX_SESSION_DURATION_SECONDS,
    AuthorizationStatus,
    ControllerAuthMode,
    ErrorCode,
    IntegrationEventStatus,
    IntegrationEventType,
    IntegrationStatus,
    NetworkProviderKind,
    SyncStatus,
)
from app.domains.network_integration.crypto import (
    NetworkIntegrationCredentialDecryptionError,
    decrypt_credentials,
    encrypt_credentials,
)
from app.domains.network_integration.exceptions import (
    PROVIDER_ERRORS_BY_CODE,
    CrossOrganizationNetworkIntegrationAccessError,
    GuestSessionNotActiveError,
    NetworkIntegrationDeauthorizationUnsupportedError,
    NetworkIntegrationFleetDeviceUnavailableError,
    NetworkIntegrationInventoryRequiresOpenApiError,
    NetworkIntegrationNotFoundError,
    NetworkIntegrationOrganizationRequiredError,
    NetworkIntegrationUrlRejectedError,
    ProviderAuthFailedError,
    ProviderSessionExpiredError,
    ProviderTimeoutError,
    ProviderUnsupportedApiError,
)
from app.domains.network_integration.models import (
    NetworkIntegration,
    NetworkIntegrationAuthorization,
    NetworkIntegrationEvent,
)
from app.domains.network_integration.providers.base import (
    NetworkProvider,
    ProviderAuthorizationResult,
    ProviderClient,
    ProviderControllerInfo,
    ProviderDevice,
    ProviderSite,
    ProviderSsid,
)
from app.domains.network_integration.router import portal_router
from app.domains.network_integration.router import router as integration_router
from app.domains.network_integration.service import (
    NetworkIntegrationService,
    redact_context,
    run_network_integration_sync_sweep,
)
from app.domains.network_integration.validators import (
    assert_address_is_public,
    normalize_client_mac,
    parse_controller_url,
    synthesize_fleet_identity,
    validate_auth_mode_credentials,
    validate_controller_url,
)
from app.domains.router.vendor_capabilities import (
    is_agent_managed,
    is_controller_managed,
)

# ============================================================================
# Shared helpers
# ============================================================================

CONTROLLER_URL = "https://controller.example.com:8043"


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _public_resolver(_host: str, _port: int) -> tuple[str, ...]:
    """A resolver that always answers with a routable public address.

    Injected so the URL tests exercise the *rules* rather than the test
    machine's DNS -- a suite that depends on a real lookup fails on a
    plane and passes in CI for reasons unrelated to the code.
    """

    async def _resolve(host: str, port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    return _resolve  # type: ignore[return-value]


async def _resolves_public(host: str, port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


async def _resolves_private(host: str, port: int) -> tuple[str, ...]:
    return ("10.0.0.5",)


async def _resolves_metadata(host: str, port: int) -> tuple[str, ...]:
    return ("169.254.169.254",)


async def _resolves_mixed(host: str, port: int) -> tuple[str, ...]:
    """A hostname with both a public and a private record.

    The dangerous case: taking ``[0]`` would make which record the
    resolver happened to order first into a security control.
    """
    return ("93.184.216.34", "127.0.0.1")


def _integration(
    *,
    organization_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    auth_mode: str = ControllerAuthMode.OPENAPI.value,
    with_credentials: bool = True,
    **overrides: object,
) -> NetworkIntegration:
    fields: dict[str, object] = {
        "organization_id": organization_id or uuid.uuid4(),
        "location_id": location_id,
        "provider": NetworkProviderKind.OMADA.value,
        "name": "Lobby controller",
        "status": IntegrationStatus.CONNECTED.value,
        "is_enabled": True,
        "base_url": CONTROLLER_URL,
        "auth_mode": auth_mode,
        "controller_id": "abc123",
        "controller_version": "5.14.20",
        "external_site_id": "site-1",
        "external_site_name": "Default",
        "guest_ssid_id": "ssid-1",
        "guest_ssid_name": "Guest WiFi",
        "credentials_encrypted": (
            encrypt_credentials({"client_id": "cid", "client_secret": "shh"})
            if with_credentials
            else None
        ),
        "session_duration_seconds": 3600,
        "sync_interval_seconds": 300,
        "provider_metadata": {},
        "last_sync_at": None,
        "last_sync_status": SyncStatus.NEVER.value,
        "last_error_code": None,
        "last_error_message": None,
        "last_error_at": None,
    }
    fields.update(overrides)
    return NetworkIntegration(**_base_fields(**fields))


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeRepository:
    """In-memory stand-in for ``NetworkIntegrationRepositoryProtocol``."""

    integrations: dict[uuid.UUID, NetworkIntegration] = field(default_factory=dict)
    events: list[NetworkIntegrationEvent] = field(default_factory=list)
    authorizations: list[NetworkIntegrationAuthorization] = field(
        default_factory=list
    )

    def add(self, integration: NetworkIntegration) -> NetworkIntegration:
        self.integrations[integration.id] = integration
        return integration

    # -- integrations --
    async def create_integration(self, **fields: object) -> NetworkIntegration:
        integration = NetworkIntegration(**_base_fields(**fields))
        self.integrations[integration.id] = integration
        return integration

    async def get_integration_by_id(
        self, integration_id: uuid.UUID, *, include_deleted: bool = False
    ) -> NetworkIntegration | None:
        integration = self.integrations.get(integration_id)
        if integration is None or (integration.is_deleted and not include_deleted):
            return None
        return integration

    async def update_integration(
        self, integration: NetworkIntegration, data: dict[str, object]
    ) -> NetworkIntegration:
        for key, value in data.items():
            setattr(integration, key, value)
        return integration

    async def soft_delete_integration(
        self, integration: NetworkIntegration
    ) -> NetworkIntegration:
        integration.is_deleted = True
        integration.deleted_at = _now()
        return integration

    async def list_integrations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        provider: str | None = None,
        status: str | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 25,
        **_: object,
    ):
        rows = [i for i in self.integrations.values() if not i.is_deleted]
        if requesting_organization_id is not None:
            rows = [
                i for i in rows if i.organization_id == requesting_organization_id
            ]
        if location_id is not None:
            rows = [i for i in rows if i.location_id == location_id]
        if provider is not None:
            rows = [i for i in rows if i.provider == provider]
        if status is not None:
            rows = [i for i in rows if i.status == status]
        if query:
            rows = [i for i in rows if query.lower() in i.name.lower()]
        params = PageParams(page=page, page_size=page_size)
        return rows, PaginationMeta.from_total(params, len(rows))

    async def resolve_display_names(self, integrations):
        return {i.id: ("Acme Hotels", "Lobby") for i in integrations}

    async def find_live_integration(
        self,
        *,
        organization_id: uuid.UUID,
        provider: str,
        base_url: str,
        external_site_id: str | None,
        exclude_id: uuid.UUID | None = None,
    ) -> NetworkIntegration | None:
        for integration in self.integrations.values():
            if (
                not integration.is_deleted
                and integration.organization_id == organization_id
                and integration.provider == provider
                and integration.base_url == base_url
                and integration.external_site_id == external_site_id
                and integration.id != exclude_id
            ):
                return integration
        return None

    async def find_enabled_integration_for_location(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID, provider: str
    ) -> NetworkIntegration | None:
        for integration in self.integrations.values():
            if (
                not integration.is_deleted
                and integration.is_enabled
                and integration.organization_id == organization_id
                and integration.location_id == location_id
                and integration.provider == provider
            ):
                return integration
        return None

    async def list_due_for_sync(self, *, now: datetime, limit: int):
        return [
            i
            for i in self.integrations.values()
            if not i.is_deleted and i.is_enabled
        ][:limit]

    # -- events --
    async def create_event(self, **fields: object) -> NetworkIntegrationEvent:
        event = NetworkIntegrationEvent(**_base_fields(**fields))
        self.events.append(event)
        return event

    async def list_events(
        self,
        *,
        integration_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ):
        rows = [e for e in self.events if e.integration_id == integration_id]
        if requesting_organization_id is not None:
            rows = [
                e for e in rows if e.organization_id == requesting_organization_id
            ]
        params = PageParams(page=page, page_size=page_size)
        return rows, PaginationMeta.from_total(params, len(rows))

    # -- authorizations --
    async def create_authorization(
        self, **fields: object
    ) -> NetworkIntegrationAuthorization:
        row = NetworkIntegrationAuthorization(**_base_fields(**fields))
        self.authorizations.append(row)
        return row

    async def update_authorization(self, authorization, data):
        for key, value in data.items():
            setattr(authorization, key, value)
        return authorization

    async def count_active_authorizations(
        self, *, integration_id=None, organization_id=None, now=None
    ) -> int:
        rows = [
            a
            for a in self.authorizations
            if a.status == AuthorizationStatus.AUTHORIZED.value
        ]
        if integration_id is not None:
            rows = [a for a in rows if a.integration_id == integration_id]
        if organization_id is not None:
            rows = [a for a in rows if a.organization_id == organization_id]
        return len(rows)

    async def find_active_authorization(self, *, integration_id, client_mac):
        for row in reversed(self.authorizations):
            if (
                row.integration_id == integration_id
                and row.client_mac == client_mac
                and row.status == AuthorizationStatus.AUTHORIZED.value
            ):
                return row
        return None

    async def platform_summary(self):
        from types import SimpleNamespace

        live = [i for i in self.integrations.values() if not i.is_deleted]
        return SimpleNamespace(
            tenant_count=len({i.organization_id for i in live}),
            integration_count=len(live),
            connected_count=len(
                [i for i in live if i.status == IntegrationStatus.CONNECTED.value]
            ),
            error_count=0,
            disabled_count=len([i for i in live if not i.is_enabled]),
            device_count=0,
            client_count=0,
            active_authorization_count=0,
            last_sync_at=None,
        )


@dataclass
class FakeProvider:
    """Hand-rolled ``NetworkProvider``. No gateway, no controller."""

    kind: str = NetworkProviderKind.OMADA.value
    # Part of the Protocol since the Master onboarding path landed: it is
    # what `create_integration_with_fleet_device` reads to decide the
    # `Router.vendor` of the fleet row, instead of `service.py` naming a
    # vendor it is not allowed to know.
    fleet_device_vendor: str = "tplink_omada"
    raise_on: dict[str, Exception] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    authorize_result: ProviderAuthorizationResult | None = None
    clients: list[ProviderClient] = field(default_factory=list)

    def _maybe_raise(self, method: str) -> None:
        self.calls.append(method)
        error = self.raise_on.get(method)
        if error is not None:
            raise error

    async def test_connection(self, config) -> ProviderControllerInfo:
        self._maybe_raise("test_connection")
        return ProviderControllerInfo(
            controller_id="abc123",
            controller_version="5.14.20",
            model="OC200",
            supports_openapi=True,
        )

    async def get_controller_info(self, config) -> ProviderControllerInfo:
        self._maybe_raise("get_controller_info")
        return ProviderControllerInfo(
            controller_id="abc123", controller_version="5.14.20"
        )

    async def list_sites(self, config) -> list[ProviderSite]:
        self._maybe_raise("list_sites")
        return [ProviderSite(site_id="site-1", name="Default", device_count=2)]

    async def list_ssids(self, config, site_id) -> list[ProviderSsid]:
        self._maybe_raise("list_ssids")
        return [ProviderSsid(ssid_id="ssid-1", name="Guest WiFi", portal_enabled=True)]

    async def list_devices(self, config, site_id) -> list[ProviderDevice]:
        self._maybe_raise("list_devices")
        return [
            ProviderDevice(
                mac="AA:BB:CC:00:00:01", device_type="ap", status="connected"
            ),
            ProviderDevice(
                mac="AA:BB:CC:00:00:02", device_type="switch", status="connected"
            ),
        ]

    async def list_clients(self, config, site_id) -> list[ProviderClient]:
        self._maybe_raise("list_clients")
        return self.clients or [
            ProviderClient(mac="11:22:33:44:55:66", ssid="Guest WiFi", is_guest=True)
        ]

    async def get_client(self, config, site_id, client_mac):
        self._maybe_raise("get_client")
        for client in self.clients:
            if client.mac == client_mac:
                return client
        return None

    async def authorize_guest(
        self, config, context, *, duration_seconds, down_kbps=None, up_kbps=None
    ) -> ProviderAuthorizationResult:
        self._maybe_raise("authorize_guest")
        return self.authorize_result or ProviderAuthorizationResult(
            authorized=True,
            expires_at=_now() + timedelta(seconds=duration_seconds),
        )

    async def deauthorize_guest(self, config, site_id, client_mac) -> bool:
        self._maybe_raise("deauthorize_guest")
        return True


@dataclass
class FakeAuditWriter:
    entries: list[dict] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> object:
        self.entries.append(dict(fields))
        return object()


@dataclass
class FakeGuestSession:
    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    status: str = "active"
    is_deleted: bool = False
    # The device that authenticated. Defaulted to the MAC these tests
    # authorize, so the existing cases keep asserting what they were written
    # to assert -- and so the *mismatch* cases below have something to
    # mismatch against. This field not existing on the fake is why the
    # missing device binding went unnoticed: a session with no device
    # modelled a guest who could authorize anything.
    device_mac: str | None = "AA:BB:CC:DD:EE:FF"

    @property
    def device_id(self):  # noqa: ANN201
        if not self.device_mac:
            return None
        return uuid.uuid5(uuid.NAMESPACE_OID, self.device_mac)


@dataclass
class FakeGuestSessionLookup:
    sessions: dict[uuid.UUID, FakeGuestSession] = field(default_factory=dict)

    async def get_session_by_id(self, session_id, *, include_deleted: bool = False):
        return self.sessions.get(session_id)

    async def get_device_by_id(self, device_id):  # noqa: ANN001, ANN201
        for session in self.sessions.values():
            if session.device_id == device_id:
                return SimpleNamespace(
                    id=device_id, mac_address=session.device_mac
                )
        return None


@dataclass
class FakeRouter:
    """The shape `RouterService.create_router` returns, and nothing more."""

    id: uuid.UUID
    location_id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    serial_number: str
    mac_address: str
    model: str
    vendor: str
    status: str = "pending_provisioning"
    settings: dict = field(default_factory=dict)


@dataclass
class FakeFleetDeviceProvisioner:
    """Stands in for `RouterService` on the Master onboarding path.

    Records every call so a test can assert on what this domain *asked
    the router domain for* -- the vendor in particular, since a fleet row
    written as the default `mikrotik` is the whole failure mode the
    vendor-capability gating exists to prevent, and it would be invisible
    in the response body.
    """

    calls: list[dict] = field(default_factory=list)
    raise_on_create: Exception | None = None
    known_locations: set[uuid.UUID] | None = None

    async def create_router(
        self,
        *,
        actor_user_id,
        location_id,
        requesting_organization_id,
        name,
        serial_number,
        mac_address,
        model,
        vendor="mikrotik",
        settings=None,
        **extra,
    ):
        self.calls.append(
            {
                "actor_user_id": actor_user_id,
                "location_id": location_id,
                "requesting_organization_id": requesting_organization_id,
                "name": name,
                "serial_number": serial_number,
                "mac_address": mac_address,
                "model": model,
                "vendor": vendor,
                "settings": settings or {},
            }
        )
        if self.raise_on_create is not None:
            raise self.raise_on_create
        return FakeRouter(
            id=uuid.uuid4(),
            location_id=location_id,
            organization_id=requesting_organization_id,
            name=name,
            serial_number=serial_number,
            mac_address=mac_address,
            model=model,
            vendor=vendor,
            settings=settings or {},
        )


def _service(
    repository: FakeRepository | None = None,
    *,
    provider: FakeProvider | None = None,
    audit: FakeAuditWriter | None = None,
    guest_lookup: FakeGuestSessionLookup | None = None,
    fleet_provisioner: FakeFleetDeviceProvisioner | None = None,
    caller_location_scope=None,
) -> NetworkIntegrationService:
    fake_provider = provider or FakeProvider()
    return NetworkIntegrationService(
        repository or FakeRepository(),
        audit_writer=audit or FakeAuditWriter(),
        guest_session_lookup=guest_lookup,
        fleet_device_provisioner=fleet_provisioner,
        provider_resolver=lambda _kind: fake_provider,
        # Without this every service-level test does a REAL DNS lookup of
        # controller.example.com, which fails offline and, worse, would
        # resolve to whatever a captive/hijacking resolver returns on some
        # other machine. The SSRF rules themselves are exercised directly
        # against validate_controller_url in TestSsrfRejection.
        url_resolver=_resolves_public,
        redis=None,
        caller_location_scope=caller_location_scope,
    )


# ============================================================================
# Credentials: both auth modes
# ============================================================================


class TestAuthModeCredentials:
    def test_openapi_mode_accepts_client_id_and_secret(self) -> None:
        result = validate_auth_mode_credentials(
            auth_mode=ControllerAuthMode.OPENAPI,
            client_id="cid",
            client_secret="secret",
            username=None,
            password=None,
        )
        assert result == {"client_id": "cid", "client_secret": "secret"}

    def test_legacy_mode_accepts_operator_username_and_password(self) -> None:
        result = validate_auth_mode_credentials(
            auth_mode=ControllerAuthMode.LEGACY,
            client_id=None,
            client_secret=None,
            username="operator",
            password="pw",
        )
        assert result == {"username": "operator", "password": "pw"}

    def test_openapi_mode_rejects_a_missing_secret(self) -> None:
        with pytest.raises(ValueError, match="client_id and client_secret"):
            validate_auth_mode_credentials(
                auth_mode=ControllerAuthMode.OPENAPI,
                client_id="cid",
                client_secret=None,
                username=None,
                password=None,
            )

    def test_openapi_mode_rejects_operator_fields(self) -> None:
        """Silently ignoring the wrong pair is what produces an
        AUTH_FAILED hours later with nothing to explain it."""
        with pytest.raises(ValueError, match="does not use an operator"):
            validate_auth_mode_credentials(
                auth_mode=ControllerAuthMode.OPENAPI,
                client_id="cid",
                client_secret="secret",
                username="operator",
                password="pw",
            )

    def test_legacy_mode_rejects_openapi_fields(self) -> None:
        with pytest.raises(ValueError, match="does not use an Open API"):
            validate_auth_mode_credentials(
                auth_mode=ControllerAuthMode.LEGACY,
                client_id="cid",
                client_secret="secret",
                username="operator",
                password="pw",
            )


class TestCredentialEncryption:
    def test_round_trips(self) -> None:
        ciphertext = encrypt_credentials({"client_id": "a", "client_secret": "b"})
        assert decrypt_credentials(ciphertext) == {
            "client_id": "a",
            "client_secret": "b",
        }

    def test_ciphertext_does_not_contain_the_plaintext(self) -> None:
        ciphertext = encrypt_credentials({"client_secret": "hunter2"})
        assert "hunter2" not in ciphertext

    def test_empty_values_are_dropped_not_stored_as_null(self) -> None:
        ciphertext = encrypt_credentials(
            {"client_id": "a", "client_secret": "b", "username": ""}
        )
        assert "username" not in decrypt_credentials(ciphertext)

    def test_tampered_ciphertext_is_refused(self) -> None:
        ciphertext = encrypt_credentials({"client_secret": "b"})
        tampered = ciphertext[:-4] + "AAAA"
        with pytest.raises(NetworkIntegrationCredentialDecryptionError):
            decrypt_credentials(tampered)


# ============================================================================
# SSRF -- MANDATORY
# ============================================================================


class TestSsrfRejection:
    """Load-bearing. ``base_url`` is user input that reaches a server-side
    HTTP client carrying a tenant's controller credentials."""

    async def test_a_public_https_url_on_an_allowed_port_is_accepted(self) -> None:
        validated = await validate_controller_url(
            CONTROLLER_URL, resolver=_resolves_public
        )
        assert validated.base_url == "https://controller.example.com:8043"

    def test_plain_http_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="plain http"):
            parse_controller_url("http://controller.example.com:8043")

    def test_a_non_http_scheme_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            parse_controller_url("file:///etc/passwd")

    def test_credentials_embedded_in_the_url_are_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="credentials"):
            parse_controller_url("https://user:pw@controller.example.com:8043")

    def test_a_port_outside_the_allowlist_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="allowlist"):
            parse_controller_url("https://controller.example.com:22")

    def test_a_path_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="no path"):
            parse_controller_url("https://controller.example.com:8043/admin")

    def test_a_query_string_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="query"):
            parse_controller_url("https://controller.example.com:8043?a=b")

    def test_control_characters_are_refused(self) -> None:
        """A URL containing a newline is a request-smuggling attempt
        against whatever client receives it, not a typo."""
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="control"):
            parse_controller_url("https://controller.example.com:8043\r\nHost: evil")

    def test_the_url_is_normalized_so_one_controller_is_one_row(self) -> None:
        scheme, host, port = parse_controller_url(
            "HTTPS://Controller.Example.COM:8043/"
        )
        assert (scheme, host, port) == ("https", "controller.example.com", 8043)

    async def test_a_host_resolving_to_rfc1918_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="private"):
            await validate_controller_url(
                CONTROLLER_URL, resolver=_resolves_private
            )

    async def test_cloud_metadata_is_refused(self) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="metadata"):
            await validate_controller_url(
                CONTROLLER_URL, resolver=_resolves_metadata
            )

    async def test_every_resolved_address_is_checked_not_just_the_first(self) -> None:
        """The DNS-rebinding-adjacent case: a hostname with one public and
        one loopback record must be refused. Taking ``[0]`` would make
        record ordering a security control."""
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="loopback"):
            await validate_controller_url(CONTROLLER_URL, resolver=_resolves_mixed)

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
        ],
    )
    def test_every_refused_address_class(self, address: str) -> None:
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            assert_address_is_public(address)

    def test_metadata_stays_refused_even_when_private_urls_are_allowed(self) -> None:
        """There is no development scenario that needs this platform to
        fetch 169.254.169.254, so the convenience flag must not reach it."""
        assert_address_is_public("10.0.0.5", allow_private=True)
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="metadata"):
            assert_address_is_public("169.254.169.254", allow_private=True)

    async def test_the_provider_revalidates_before_every_request(self) -> None:
        """The re-validation is the control that closes DNS rebinding: a
        row written weeks ago whose hostname now resolves privately must
        not be dialled."""
        from app.domains.network_integration.providers.omada import OmadaProvider

        provider = OmadaProvider()
        config_module = __import__(
            "app.domains.network_integration.providers.base",
            fromlist=["ProviderConnectionConfig"],
        )
        config = config_module.ProviderConnectionConfig(
            provider="omada",
            base_url="https://controller.example.com:22",
            auth_mode="openapi",
            credentials={"client_id": "a", "client_secret": "b"},
        )
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await provider.test_connection(config)


class TestMacNormalization:
    def test_dash_separated_omada_redirect_form_is_normalized(self) -> None:
        assert normalize_client_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_colon_separated_is_normalized(self) -> None:
        assert normalize_client_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_garbage_is_refused(self) -> None:
        with pytest.raises(ValueError, match="Not a valid MAC"):
            normalize_client_mac("not-a-mac")


# ============================================================================
# Tenant isolation -- MANDATORY
# ============================================================================


class TestTenantIsolation:
    """Tenant A must not reach tenant B's integration.

    ``base_url`` is where this platform sends a tenant's decrypted
    controller credentials, so a cross-tenant *write* here is a credential
    exfiltration primitive: repoint the victim's URL at a host you
    control, wait for the sync sweep, receive their credentials. Every
    assertion below is that class of bug, not a data-visibility nicety.
    """

    async def test_foreign_integration_cannot_be_read(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.get_integration(
                integration.id, requesting_organization_id=attacker
            )

    async def test_foreign_integration_cannot_be_updated(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.update_integration(
                integration.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=attacker,
                fields={"name": "pwned"},
            )
        assert integration.name == "Lobby controller"

    async def test_foreign_integrations_base_url_cannot_be_repointed(self) -> None:
        """The exfiltration path, pinned explicitly."""
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.update_integration(
                integration.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=attacker,
                fields={"base_url": "https://attacker.example.com:8043"},
            )
        assert integration.base_url == CONTROLLER_URL

    async def test_foreign_integration_cannot_be_deleted(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.delete_integration(
                integration.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=attacker,
            )
        assert integration.is_deleted is False

    async def test_foreign_credentials_cannot_be_rotated(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        original = integration.credentials_encrypted
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.rotate_credentials(
                integration.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=attacker,
                auth_mode=ControllerAuthMode.OPENAPI.value,
                client_id="x",
                client_secret="y",
            )
        assert integration.credentials_encrypted == original

    async def test_foreign_integration_cannot_be_synced(self) -> None:
        """A manual sync is a real outbound call -- letting tenant A
        trigger it against tenant B's controller is both cross-tenant and
        a way to make this platform generate traffic at a third party."""
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.sync_integration(
                integration.id, requesting_organization_id=attacker
            )

    async def test_foreign_events_cannot_be_read(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        service = _service(repo)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await service.list_events(
                integration.id, requesting_organization_id=attacker
            )

    @pytest.mark.parametrize(
        "method_name",
        ["list_sites", "list_ssids", "list_devices", "list_clients"],
    )
    async def test_foreign_live_reads_are_refused(self, method_name: str) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=victim))
        provider = FakeProvider()
        service = _service(repo, provider=provider)
        with pytest.raises(CrossOrganizationNetworkIntegrationAccessError):
            await getattr(service, method_name)(
                integration.id, requesting_organization_id=attacker
            )
        # The tenant check must happen before the row is used for
        # anything -- the provider must never have been called.
        assert provider.calls == []

    async def test_own_integration_is_reachable(self) -> None:
        owner = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=owner))
        service = _service(repo)
        loaded = await service.get_integration(
            integration.id, requesting_organization_id=owner
        )
        assert loaded.id == integration.id

    async def test_a_missing_row_is_a_404_not_a_403(self) -> None:
        service = _service(FakeRepository())
        with pytest.raises(NetworkIntegrationNotFoundError):
            await service.get_integration(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_list_refuses_a_null_organization_on_the_customer_path(
        self,
    ) -> None:
        """``CurrentOrganization`` is ``None`` for a GLOBAL caller, and
        ``None`` means "no filter" downstream. On a customer route that
        would silently return every tenant's integrations."""
        repo = FakeRepository()
        repo.add(_integration(organization_id=uuid.uuid4()))
        repo.add(_integration(organization_id=uuid.uuid4()))
        service = _service(repo)
        with pytest.raises(NetworkIntegrationOrganizationRequiredError):
            await service.list_integrations(requesting_organization_id=None)

    async def test_create_refuses_a_null_organization(self) -> None:
        service = _service(FakeRepository())
        with pytest.raises(NetworkIntegrationOrganizationRequiredError):
            await service.create_integration(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=None,
                provider="omada",
                name="x",
                base_url=CONTROLLER_URL,
                auth_mode="openapi",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_the_platform_list_is_deliberately_cross_tenant(self) -> None:
        """The unscoped read exists and is reached by name -- what gates it
        is ``scope=ScopeType.GLOBAL`` on the route, not this method."""
        repo = FakeRepository()
        repo.add(_integration(organization_id=uuid.uuid4()))
        repo.add(_integration(organization_id=uuid.uuid4()))
        service = _service(repo)
        rows, _meta, names = await service.list_platform_integrations()
        assert len(rows) == 2
        assert all(name in names for name in [r.id for r in rows])

    async def test_location_confinement_refuses_another_site(self) -> None:
        """Same tenant, different site. The organization comparison sees
        nothing wrong -- this is the within-tenant half."""
        from app.domains.network_integration.exceptions import (
            CrossLocationNetworkIntegrationAccessError,
        )

        org = uuid.uuid4()
        site_a, site_b = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=site_b)
        )
        service = _service(repo, caller_location_scope=frozenset({site_a}))
        with pytest.raises(CrossLocationNetworkIntegrationAccessError):
            await service.get_integration(
                integration.id, requesting_organization_id=org
            )

    async def test_an_unconfined_caller_reaches_any_of_their_own_sites(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=uuid.uuid4())
        )
        service = _service(repo, caller_location_scope=None)
        assert (
            await service.get_integration(
                integration.id, requesting_organization_id=org
            )
        ).id == integration.id


# ============================================================================
# CRUD
# ============================================================================


class TestIntegrationCrud:
    async def test_create_stores_a_normalized_url_and_encrypts_credentials(
        self,
    ) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        service = _service(repo)
        integration = await service.create_integration(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            provider="omada",
            name="Lobby",
            base_url="HTTPS://Controller.Example.COM:8043/",
            auth_mode="openapi",
            external_site_id="site-1",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="secret",
        )
        assert integration.base_url == "https://controller.example.com:8043"
        assert integration.credentials_encrypted is not None
        assert "secret" not in integration.credentials_encrypted
        assert integration.status == IntegrationStatus.CONNECTING.value

    async def test_create_without_credentials_is_unconfigured_not_connected(
        self,
    ) -> None:
        """Nothing claims a working connection this platform has not made."""
        service = _service(FakeRepository())
        integration = await service.create_integration(
            actor_user_id=None,
            requesting_organization_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )
        assert integration.status == IntegrationStatus.UNCONFIGURED.value
        assert integration.credentials_encrypted is None

    async def test_create_refuses_an_ssrf_url(self) -> None:
        service = _service(FakeRepository())
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.create_integration(
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
                provider="omada",
                name="Lobby",
                base_url="http://169.254.169.254:8043",
                auth_mode="openapi",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_create_refuses_an_unknown_provider(self) -> None:
        from app.domains.network_integration.exceptions import (
            UnsupportedNetworkProviderError,
        )

        service = _service(FakeRepository())
        with pytest.raises(UnsupportedNetworkProviderError):
            await service.create_integration(
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
                provider="ubiquiti",
                name="x",
                base_url=CONTROLLER_URL,
                auth_mode="openapi",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_duplicate_controller_and_site_is_a_conflict(self) -> None:
        from app.domains.network_integration.exceptions import (
            NetworkIntegrationAlreadyExistsError,
        )

        org = uuid.uuid4()
        repo = FakeRepository()
        repo.add(_integration(organization_id=org, external_site_id="site-1"))
        service = _service(repo)
        with pytest.raises(NetworkIntegrationAlreadyExistsError):
            await service.create_integration(
                actor_user_id=None,
                requesting_organization_id=org,
                provider="omada",
                name="Duplicate",
                base_url=CONTROLLER_URL,
                auth_mode="openapi",
                external_site_id="site-1",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_changing_the_base_url_revalidates_it(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.update_integration(
                integration.id,
                actor_user_id=None,
                requesting_organization_id=org,
                fields={"base_url": "https://controller.example.com:23"},
            )

    async def test_changing_the_base_url_resets_the_status_ladder(self) -> None:
        """What was CONNECTED was connected to the *old* controller."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        updated = await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"base_url": "https://other.example.com:8043"},
        )
        assert updated.status == IntegrationStatus.CONNECTING.value
        assert updated.controller_id is None

    async def test_changing_the_auth_mode_clears_the_stored_credentials(
        self,
    ) -> None:
        """Keeping them would leave the row claiming has_credentials while
        every call fails AUTH_FAILED with nothing explaining why."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        updated = await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"auth_mode": "legacy"},
        )
        assert updated.credentials_encrypted is None
        assert updated.status == IntegrationStatus.UNCONFIGURED.value

    async def test_delete_destroys_the_stored_credentials(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        deleted = await service.delete_integration(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        assert deleted.is_deleted is True
        assert deleted.credentials_encrypted is None

    async def test_rotation_replaces_without_reading_the_old_value(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        before = integration.credentials_encrypted
        service = _service(repo)
        updated = await service.rotate_credentials(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            auth_mode="openapi",
            client_id="new-cid",
            client_secret="new-secret",
        )
        assert updated.credentials_encrypted != before
        assert decrypt_credentials(updated.credentials_encrypted) == {
            "client_id": "new-cid",
            "client_secret": "new-secret",
        }
        assert updated.status == IntegrationStatus.CONNECTING.value


class TestMasterFleetOnboarding:
    """`POST /network-integrations/platform/onboard` -- contract §11.6.

    The reason this path exists at all is a NOT NULL constraint two
    domains away: `guest_sessions.router_id`. So the tests that matter
    most here are not "did it return 201" but "is there a fleet row, does
    it carry the right vendor, and does the pair roll back together".
    """

    async def test_onboarding_creates_a_linked_fleet_device(self) -> None:
        org, location = uuid.uuid4(), uuid.uuid4()
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        integration, router = await service.create_integration_with_fleet_device(
            actor_user_id=uuid.uuid4(),
            organization_id=org,
            location_id=location,
            provider="omada",
            name="Lobby controller",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="Omada Software Controller",
            external_site_id="site-1",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="secret",
        )

        assert integration.router_id == router.id
        assert integration.organization_id == org
        assert integration.location_id == location
        assert len(provisioner.calls) == 1

    async def test_the_fleet_row_is_never_written_as_mikrotik(self) -> None:
        """The default of `Router.vendor` is `mikrotik`, and every
        RouterOS-assuming sweep in the product reads that column. A fleet
        row for an Omada controller carrying the default would be reported
        as a broken MikroTik rather than as a controller -- which is the
        exact failure §11.5 is about."""
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        _, router = await service.create_integration_with_fleet_device(
            actor_user_id=None,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="TP-Link OC200",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert provisioner.calls[0]["vendor"] == "tplink_omada"
        assert router.vendor == "tplink_omada"
        assert not is_agent_managed(router.vendor)
        assert is_controller_managed(router.vendor)

    async def test_the_vendor_comes_from_the_provider_not_from_the_service(
        self,
    ) -> None:
        """`service.py` names no vendor (see `TestProviderSeamIsolation`).
        A second provider therefore registers its own fleet vendor rather
        than editing a branch here."""
        provider = FakeProvider()
        provider.fleet_device_vendor = "some_other_vendor"
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(
            FakeRepository(), provider=provider, fleet_provisioner=provisioner
        )

        await service.create_integration_with_fleet_device(
            actor_user_id=None,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="Controller",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert provisioner.calls[0]["vendor"] == "some_other_vendor"

    async def test_a_software_controller_gets_a_visibly_synthetic_identity(
        self,
    ) -> None:
        """A software controller has no serial plate and no MAC of its
        own. What it must never get is a fabricated *vendor* MAC, which
        could collide with a real access point in every MAC-keyed lookup
        in the product."""
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        integration, router = await service.create_integration_with_fleet_device(
            actor_user_id=None,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="Omada Software Controller",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert router.serial_number.startswith("OMADA-")
        # Locally administered (bit 1 of the first octet set), unicast
        # (bit 0 clear) -- IEEE 802 reserves this for administrator-assigned
        # addresses, so no manufacturer may ever burn it into hardware.
        first_octet = int(router.mac_address.split(":")[0], 16)
        assert first_octet & 0b10 == 0b10
        assert first_octet & 0b01 == 0
        assert router.settings["synthetic_identity"] is True
        # Derived from the integration id, so a retried onboarding cannot
        # produce a second inventory row for one controller.
        expected = synthesize_fleet_identity(integration.id)
        assert (router.serial_number, router.mac_address) == expected

    async def test_real_hardware_identifiers_are_used_when_supplied(self) -> None:
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        _, router = await service.create_integration_with_fleet_device(
            actor_user_id=None,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="TP-Link OC300",
            serial_number="21A8B0C1D2E3",
            mac_address="AA:BB:CC:DD:EE:FF",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert router.serial_number == "21A8B0C1D2E3"
        assert router.mac_address == "AA:BB:CC:DD:EE:FF"
        assert router.settings["synthetic_identity"] is False

    async def test_the_location_pairing_is_verified_by_the_router_domain(
        self,
    ) -> None:
        """The organization id arrives in the request body on this route,
        because a GLOBAL-scoped operator has none of their own. What makes
        that safe is that the pair is re-checked: the router domain's
        location lookup runs with this organization id and rejects a
        location belonging to someone else."""
        org = uuid.uuid4()
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        await service.create_integration_with_fleet_device(
            actor_user_id=None,
            organization_id=org,
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="Controller",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert provisioner.calls[0]["requesting_organization_id"] == org

    async def test_a_fleet_failure_leaves_no_half_onboarded_controller(
        self,
    ) -> None:
        """Both writes share one session and one transaction, so a failure
        registering the device must propagate rather than be swallowed
        into a 201 for an integration whose venue still cannot log a guest
        in."""
        provisioner = FakeFleetDeviceProvisioner(
            raise_on_create=RuntimeError("duplicate serial number")
        )
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        with pytest.raises(RuntimeError):
            await service.create_integration_with_fleet_device(
                actor_user_id=None,
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                provider="omada",
                name="Lobby",
                base_url=CONTROLLER_URL,
                auth_mode="openapi",
                controller_model="Controller",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_an_ssrf_url_is_rejected_before_any_fleet_row_is_written(
        self,
    ) -> None:
        """The integration's own guards run first, so the common rejection
        path never touches another domain's table."""
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.create_integration_with_fleet_device(
                actor_user_id=None,
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                provider="omada",
                name="Lobby",
                base_url="http://169.254.169.254:8043",
                auth_mode="openapi",
                controller_model="Controller",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

        assert provisioner.calls == []

    async def test_onboarding_without_a_provisioner_refuses_rather_than_degrades(
        self,
    ) -> None:
        """Falling back to a plain create would return 201 for a venue
        that still cannot log a guest in -- the worst possible outcome to
        report as success."""
        service = _service(FakeRepository(), fleet_provisioner=None)

        with pytest.raises(NetworkIntegrationFleetDeviceUnavailableError):
            await service.create_integration_with_fleet_device(
                actor_user_id=None,
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                provider="omada",
                name="Lobby",
                base_url=CONTROLLER_URL,
                auth_mode="openapi",
                controller_model="Controller",
                session_duration_seconds=3600,
                sync_interval_seconds=300,
            )

    async def test_customer_self_service_still_creates_no_fleet_row(self) -> None:
        """The self-service path is unchanged and must stay that way: a
        tenant connecting a controller the platform never deployed does
        not get an inventory device."""
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(FakeRepository(), fleet_provisioner=provisioner)

        integration = await service.create_integration(
            actor_user_id=None,
            requesting_organization_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )

        assert integration.router_id is None
        assert provisioner.calls == []

    async def test_the_onboarding_is_audited_as_its_own_action(self) -> None:
        audit = FakeAuditWriter()
        service = _service(
            FakeRepository(),
            audit=audit,
            fleet_provisioner=FakeFleetDeviceProvisioner(),
        )

        await service.create_integration_with_fleet_device(
            actor_user_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            controller_model="Controller",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="secret",
        )

        actions = [entry.get("action") for entry in audit.entries]
        assert "network_integration_fleet_device_onboarded" in actions
        # And no secret rode along in any of them.
        assert "secret" not in json.dumps(audit.entries, default=str)


class TestPlatformOnboardRequest:
    """The request contract for `POST /network-integrations/platform/onboard`.

    Worth its own tests because two of its rules are *refusals*, and a
    refusal that quietly stopped firing would not break anything visible --
    it would write a subtly wrong fleet row.
    """

    @staticmethod
    def _body(**overrides):
        base = {
            "organization_id": str(uuid.uuid4()),
            "location_id": str(uuid.uuid4()),
            "provider": "omada",
            "name": "Lobby controller",
            "base_url": CONTROLLER_URL,
            "auth_mode": "openapi",
            "controller_model": "OC200",
            "client_id": "cid",
            "client_secret": "sec",
        }
        base.update(overrides)
        return base

    def test_a_software_controller_needs_neither_identifier(self) -> None:
        from app.domains.network_integration.schemas import PlatformOnboardRequest

        request = PlatformOnboardRequest.model_validate(self._body())
        assert request.serial_number is None
        assert request.mac_address is None

    def test_real_hardware_may_supply_both(self) -> None:
        from app.domains.network_integration.schemas import PlatformOnboardRequest

        request = PlatformOnboardRequest.model_validate(
            self._body(serial_number="21A8B0C1D2E3", mac_address="AA:BB:CC:DD:EE:FF")
        )
        assert request.serial_number == "21A8B0C1D2E3"

    @pytest.mark.parametrize(
        "half",
        [
            {"serial_number": "21A8B0C1D2E3"},
            {"mac_address": "AA:BB:CC:DD:EE:FF"},
        ],
    )
    def test_half_a_hardware_identity_is_refused(self, half: dict) -> None:
        """A real serial paired with a minted MAC reads as a genuine
        hardware record in the fleet table and is not one."""
        import pydantic

        from app.domains.network_integration.schemas import PlatformOnboardRequest

        with pytest.raises(pydantic.ValidationError):
            PlatformOnboardRequest.model_validate(self._body(**half))

    def test_the_tenant_and_venue_are_both_required(self) -> None:
        """Unlike customer self-service, where the organization comes from a
        header and the location is optional. Neither can be inferred here:
        a platform operator has no organization of their own, and the fleet
        row this writes has to be somewhere."""
        import pydantic

        from app.domains.network_integration.schemas import PlatformOnboardRequest

        for missing in ("organization_id", "location_id"):
            body = self._body()
            del body[missing]
            with pytest.raises(pydantic.ValidationError):
                PlatformOnboardRequest.model_validate(body)

    def test_no_response_field_could_carry_a_credential(self) -> None:
        from app.domains.network_integration.schemas import PlatformOnboardResponse

        fields = set(PlatformOnboardResponse.model_fields)
        for forbidden in ("client_secret", "password", "credentials"):
            assert forbidden not in fields


class TestSyntheticFleetIdentity:
    """`synthesize_fleet_identity` -- the MAC rules are a correctness
    control, not cosmetics: this address goes into a column that client
    lookups, MAC authorization and DHCP leases all join on."""

    def test_it_is_deterministic(self) -> None:
        """A retried onboarding must collide with its own previous row on
        the unique index rather than create a second inventory device for
        one controller."""
        integration_id = uuid.uuid4()
        assert synthesize_fleet_identity(integration_id) == synthesize_fleet_identity(
            integration_id
        )

    def test_two_controllers_do_not_share_an_identity(self) -> None:
        first = synthesize_fleet_identity(uuid.uuid4())
        second = synthesize_fleet_identity(uuid.uuid4())
        assert first[0] != second[0]
        assert first[1] != second[1]

    def test_the_mac_is_locally_administered_and_unicast(self) -> None:
        """IEEE 802 reserves this space for administrator-assigned
        addresses and forbids a manufacturer from burning one into
        hardware -- which is what makes a collision with a real access
        point impossible by construction rather than merely unlikely."""
        for _ in range(50):
            _serial, mac = synthesize_fleet_identity(uuid.uuid4())
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0b10 == 0b10, mac
            assert first_octet & 0b01 == 0, mac

    def test_the_serial_is_visibly_minted(self) -> None:
        serial, _mac = synthesize_fleet_identity(uuid.uuid4())
        assert serial.startswith("OMADA-")

    def test_neither_value_leaks_the_database_key(self) -> None:
        """Both columns are shown in the fleet table and land in support
        tickets and screenshots."""
        integration_id = uuid.uuid4()
        serial, mac = synthesize_fleet_identity(integration_id)
        assert integration_id.hex[:8] not in serial.replace("-", "").lower()
        assert integration_id.hex[:8] not in mac.replace(":", "").lower()


class TestThePortalAuthorizeBindsTheDeviceToTheSession:
    """The MAC being authorized must be the one that authenticated.

    Every other check on this path -- ACTIVE session, matching organization,
    matching location, integration resolved from the SESSION's venue -- is
    satisfied by a guest who did everything honestly. None of them says
    anything about *which device* is being let onto the network. Without the
    binding, that guest completes OTP once and then puts a stranger's phone
    on the venue's WiFi, and on a controller older than 5.13 there is no
    deauthorization call to take it back off again.
    """

    @staticmethod
    def _fixture(device_mac: str | None):
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        integration = _integration(
            organization_id=org,
            location_id=location,
            status=IntegrationStatus.CONNECTED.value,
            external_site_id="site-1",
            credentials_encrypted=encrypt_credentials(
                {"client_id": "cid", "client_secret": "sec"}
            ),
        )
        repo = FakeRepository()
        repo.add(integration)
        lookup = FakeGuestSessionLookup(
            {
                session_id: FakeGuestSession(
                    session_id, org, location, device_mac=device_mac
                )
            }
        )
        provider = FakeProvider()
        service = _service(repo, provider=provider, guest_lookup=lookup)
        return service, provider, session_id, org, location

    async def test_a_stranger_s_device_is_refused(self) -> None:
        """The whole point: an honest session, the right venue, someone
        else's hardware."""
        service, provider, session_id, org, location = self._fixture(
            "AA:BB:CC:DD:EE:FF"
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                client_mac="11:22:33:44:55:66",
                site="site-1",
                provider="omada",
            )
        assert "authorize_guest" not in provider.calls, (
            "the controller was asked to authorize a device the session "
            "never presented"
        )

    async def test_the_session_s_own_device_is_allowed(self) -> None:
        service, provider, session_id, org, location = self._fixture(
            "AA:BB:CC:DD:EE:FF"
        )
        result = await service.authorize_portal_client(
            session_id=session_id,
            organization_id=org,
            location_id=location,
            client_mac="AA:BB:CC:DD:EE:FF",
            site="site-1",
            provider="omada",
        )
        assert result.authorized is True

    async def test_the_comparison_is_on_the_normalized_form(self) -> None:
        """Omada's redirect uses dashes, its API replies sometimes use
        colons. A binding that compared raw strings would refuse the
        session's own device for a punctuation difference -- which would
        read as "the portal is broken" rather than as a security control."""
        service, _provider, session_id, org, location = self._fixture(
            "AA:BB:CC:DD:EE:FF"
        )
        result = await service.authorize_portal_client(
            session_id=session_id,
            organization_id=org,
            location_id=location,
            client_mac="aa-bb-cc-dd-ee-ff",
            site="site-1",
            provider="omada",
        )
        assert result.authorized is True

    async def test_a_session_with_no_device_is_refused(self) -> None:
        """`GuestSession.device_id` is nullable, but on this path the MAC
        always arrives on Omada's own redirect. No device means the binding
        cannot be established, and an authorization that cannot be bound is
        the one worth refusing."""
        service, provider, session_id, org, location = self._fixture(None)
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                client_mac="AA:BB:CC:DD:EE:FF",
                site="site-1",
                provider="omada",
            )
        assert "authorize_guest" not in provider.calls

    async def test_the_refusal_is_indistinguishable_from_any_other(self) -> None:
        """The caller holds no credentials. Telling a prober that the
        session was fine and only the device was wrong hands them the half
        to vary."""
        service, _p, session_id, org, location = self._fixture("AA:BB:CC:DD:EE:FF")
        wrong_device = None
        try:
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                client_mac="11:22:33:44:55:66",
                site="site-1",
                provider="omada",
            )
        except GuestSessionNotActiveError as exc:
            wrong_device = str(exc)

        no_session = None
        try:
            await service.authorize_portal_client(
                session_id=uuid.uuid4(),
                organization_id=org,
                location_id=location,
                client_mac="AA:BB:CC:DD:EE:FF",
                site="site-1",
                provider="omada",
            )
        except GuestSessionNotActiveError as exc:
            no_session = str(exc)

        assert wrong_device == no_session


class TestCredentialsAreNeverReturned:
    """The response builder has no branch that could emit a secret."""

    def test_the_response_model_has_no_credential_field(self) -> None:
        from app.domains.network_integration.schemas import (
            NetworkIntegrationResponse,
        )

        fields = set(NetworkIntegrationResponse.model_fields)
        for forbidden in (
            "client_id",
            "client_secret",
            "username",
            "password",
            "credentials",
            "credentials_encrypted",
        ):
            assert forbidden not in fields
        assert "has_credentials" in fields

    def test_the_rendered_response_reports_only_a_boolean(self) -> None:
        from app.domains.network_integration.router import _integration_response

        integration = _integration()
        payload = _integration_response(integration).model_dump()
        assert payload["has_credentials"] is True
        serialized = str(payload)
        assert "shh" not in serialized
        assert integration.credentials_encrypted not in serialized

    def test_the_model_repr_does_not_carry_the_url_or_ciphertext(self) -> None:
        integration = _integration()
        rendered = repr(integration)
        assert integration.credentials_encrypted not in rendered
        assert CONTROLLER_URL not in rendered


class TestRedaction:
    def test_secret_keys_are_stripped_from_a_context_payload(self) -> None:
        result = redact_context(
            {"client_secret": "shh", "base_url": CONTROLLER_URL, "ok": 1}
        )
        assert result["client_secret"] == "[redacted]"
        assert result["base_url"] == CONTROLLER_URL

    def test_redaction_is_recursive_and_case_insensitive(self) -> None:
        result = redact_context({"outer": {"PASSWORD": "pw", "Cookie": "c"}})
        assert result["outer"]["PASSWORD"] == "[redacted]"
        assert result["outer"]["Cookie"] == "[redacted]"

    def test_redaction_handles_lists(self) -> None:
        result = redact_context([{"token": "t"}, {"safe": "s"}])
        assert result[0]["token"] == "[redacted]"
        assert result[1]["safe"] == "s"

    def test_deep_nesting_is_bounded_rather_than_recursing_forever(self) -> None:
        payload: dict = {}
        cursor = payload
        for _ in range(30):
            child: dict = {}
            cursor["next"] = child
            cursor = child
        assert redact_context(payload) is not None

    async def test_a_rotation_event_records_field_names_not_values(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        await service.rotate_credentials(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            auth_mode="openapi",
            client_id="cid",
            client_secret="super-secret-value",
        )
        rendered = str([e.context for e in repo.events])
        assert "super-secret-value" not in rendered
        assert "credential_fields" in rendered


# ============================================================================
# Connection testing
# ============================================================================


class TestConnectionTesting:
    async def test_a_successful_probe_records_the_discovered_controller(
        self,
    ) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, controller_version=None)
        )
        service = _service(repo)
        info, error = await service.test_integration_connection(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        assert error is None
        assert info.controller_version == "5.14.20"
        assert integration.status == IntegrationStatus.CONNECTED.value
        assert integration.controller_version == "5.14.20"

    async def test_invalid_credentials_set_auth_failed_not_connection_failed(
        self,
    ) -> None:
        """The distinction is the operational point: one needs a human with
        the controller password, the other needs someone to look at the
        network."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(
            raise_on={"test_connection": ProviderAuthFailedError()}
        )
        service = _service(repo, provider=provider)
        info, error = await service.test_integration_connection(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        assert info is None
        assert error.code is ErrorCode.AUTH_FAILED
        assert integration.status == IntegrationStatus.AUTH_FAILED.value
        assert integration.last_error_code == ErrorCode.AUTH_FAILED.value

    async def test_a_timeout_sets_connection_failed(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(raise_on={"test_connection": ProviderTimeoutError()})
        service = _service(repo, provider=provider)
        _info, error = await service.test_integration_connection(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        assert error.code is ErrorCode.TIMEOUT
        assert integration.status == IntegrationStatus.CONNECTION_FAILED.value

    async def test_session_expiry_is_treated_as_an_auth_problem(self) -> None:
        """The gateway re-logs-in once and gives up (contract §2). By the
        time this domain sees OMADA_SESSION_EXPIRED, the retry already
        happened, so it is an auth state, not a transient blip."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(
            raise_on={"test_connection": ProviderSessionExpiredError()}
        )
        service = _service(repo, provider=provider)
        _info, error = await service.test_integration_connection(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        assert error.code is ErrorCode.SESSION_EXPIRED
        assert integration.status == IntegrationStatus.AUTH_FAILED.value

    async def test_a_decryption_failure_reads_as_an_auth_failure(self) -> None:
        """"Your stored secret cannot be decrypted" is a statement about
        this platform's key management and has no place in a customer's
        API response -- but the practical consequence is identical."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        integration.credentials_encrypted = "not-a-fernet-token"
        service = _service(repo)
        with pytest.raises(ProviderAuthFailedError):
            await service.test_integration_connection(
                integration.id, actor_user_id=None, requesting_organization_id=org
            )

    async def test_the_unsaved_probe_persists_nothing_but_audits(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        audit = FakeAuditWriter()
        service = _service(repo, audit=audit)
        info, error = await service.test_connection_unsaved(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            provider="omada",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            client_id="cid",
            client_secret="secret",
        )
        assert error is None and info is not None
        assert repo.integrations == {}
        assert repo.events == []
        assert len(audit.entries) == 1
        assert "secret" not in str(audit.entries)


# ============================================================================
# Live reads, and CR-002 (legacy mode cannot read inventory)
# ============================================================================


class TestLiveReads:
    async def test_sites_load_from_the_controller(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        sites = await service.list_sites(
            integration.id, requesting_organization_id=org
        )
        assert [s.site_id for s in sites] == ["site-1"]

    async def test_devices_load_from_the_controller(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        service = _service(repo)
        devices = await service.list_devices(
            integration.id, requesting_organization_id=org
        )
        assert len(devices) == 2

    async def test_client_lookup_returns_the_controllers_view(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(
            clients=[
                ProviderClient(
                    mac="11:22:33:44:55:66",
                    ssid="Guest WiFi",
                    is_guest=True,
                    is_authorized=None,
                )
            ]
        )
        service = _service(repo, provider=provider)
        clients = await service.list_clients(
            integration.id, requesting_organization_id=org
        )
        assert clients[0].mac == "11:22:33:44:55:66"
        # Three-state and never collapsed to False -- rendering "not
        # authorized" for a guest who is online is an invented fact.
        assert clients[0].is_authorized is None

    async def test_a_disabled_integration_refuses_live_reads(self) -> None:
        from app.domains.network_integration.exceptions import (
            NetworkIntegrationDisabledError,
        )

        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org, is_enabled=False))
        service = _service(repo)
        with pytest.raises(NetworkIntegrationDisabledError):
            await service.list_devices(
                integration.id, requesting_organization_id=org
            )

    async def test_a_read_failure_sets_sync_error_not_connection_failed(
        self,
    ) -> None:
        """Authentication demonstrably worked recently enough for the row
        to be CONNECTED, so "cannot connect" would send the operator to
        check something that is not wrong."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(
            raise_on={"list_devices": ProviderUnsupportedApiError()}
        )
        service = _service(repo, provider=provider)
        with pytest.raises(ProviderUnsupportedApiError):
            await service.list_devices(
                integration.id, requesting_organization_id=org
            )
        assert integration.status == IntegrationStatus.SYNC_ERROR.value


class TestLegacyModeCannotReadInventory:
    """Contract change CR-002.

    An empty list here would read to a venue owner as *"you have no access
    points"* -- a false statement about their hardware, produced by this
    platform, on the screen they use to decide whether their network
    works.
    """

    @pytest.mark.parametrize(
        "method_name",
        ["list_sites", "list_ssids", "list_devices", "list_clients"],
    )
    async def test_every_inventory_read_refuses_legacy_mode(
        self, method_name: str
    ) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(
                organization_id=org, auth_mode=ControllerAuthMode.LEGACY.value
            )
        )
        provider = FakeProvider()
        service = _service(repo, provider=provider)
        with pytest.raises(NetworkIntegrationInventoryRequiresOpenApiError) as caught:
            await getattr(service, method_name)(
                integration.id, requesting_organization_id=org
            )
        assert caught.value.code is ErrorCode.API_UNSUPPORTED
        assert caught.value.status_code == 501
        # Refused before a request is issued -- the controller's own
        # refusal reads as "wrong password" and sends operators debugging
        # a credential that is fine.
        assert provider.calls == []

    async def test_the_error_names_the_fix_and_says_the_portal_still_works(
        self,
    ) -> None:
        error = NetworkIntegrationInventoryRequiresOpenApiError("devices")
        assert "Open API" in error.message
        assert "captive portal continues to work" in error.message
        assert error.data["requires_auth_mode"] == "openapi"

    async def test_legacy_mode_can_still_authorize_a_guest(self) -> None:
        """Legacy mode is not degraded -- it is the mode the captive
        portal needs, and the only one on controllers below v5.13."""
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        repo = FakeRepository()
        repo.add(
            _integration(
                organization_id=org,
                location_id=location,
                auth_mode=ControllerAuthMode.LEGACY.value,
            )
        )
        lookup = FakeGuestSessionLookup(
            {session_id: FakeGuestSession(session_id, org, location)}
        )
        service = _service(repo, guest_lookup=lookup)
        outcome = await service.authorize_portal_client(
            session_id=session_id,
            organization_id=org,
            location_id=location,
            provider="omada",
            client_mac="AA-BB-CC-DD-EE-FF",
            site="site-1",
        )
        assert outcome.authorized is True


# ============================================================================
# Portal authorize -- the captive-portal integration flow
# ============================================================================


class TestPortalAuthorize:
    def _setup(
        self,
        *,
        session_status: str = "active",
        provider: FakeProvider | None = None,
        session_org: uuid.UUID | None = None,
        session_location: uuid.UUID | None = None,
    ):
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=location)
        )
        session = FakeGuestSession(
            session_id,
            session_org or org,
            session_location or location,
            status=session_status,
        )
        lookup = FakeGuestSessionLookup({session_id: session})
        service = _service(repo, provider=provider, guest_lookup=lookup)
        return service, repo, integration, org, location, session_id

    async def test_the_full_flow_authorizes_and_records_a_row(self) -> None:
        service, repo, integration, org, location, session_id = self._setup()
        outcome = await service.authorize_portal_client(
            session_id=session_id,
            organization_id=org,
            location_id=location,
            provider="omada",
            client_mac="AA-BB-CC-DD-EE-FF",
            site="site-1",
            ap_mac="11:11:11:11:11:11",
            ssid_name="Guest WiFi",
            radio_id=1,
            t="1725945600000",
            redirect_url="https://example.com/welcome",
        )
        assert outcome.authorized is True
        assert outcome.provider == "omada"
        assert outcome.expires_at is not None
        assert outcome.redirect_url == "https://example.com/welcome"

        assert len(repo.authorizations) == 1
        row = repo.authorizations[0]
        assert row.status == AuthorizationStatus.AUTHORIZED.value
        # Normalized to the canonical form, not stored as it arrived.
        assert row.client_mac == "AA:BB:CC:DD:EE:FF"
        assert row.integration_id == integration.id
        assert row.guest_session_id == session_id

    async def test_an_inactive_session_is_refused(self) -> None:
        service, _repo, _i, org, location, session_id = self._setup(
            session_status="expired"
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_terminated_session_is_refused(self) -> None:
        """TERMINATED is the punitive kill an admin used to throw an
        abusive guest off. Honouring it here would hand them a fresh
        controller authorization."""
        service, _repo, _i, org, location, session_id = self._setup(
            session_status="terminated"
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_an_unknown_session_is_refused(self) -> None:
        service, _repo, _i, org, location, _sid = self._setup()
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=uuid.uuid4(),
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_session_from_another_organization_is_refused(self) -> None:
        """Pairing a session id with a different venue's ids must not
        authorize anything on that venue's controller."""
        service, _repo, _i, org, location, session_id = self._setup(
            session_org=uuid.uuid4()
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_session_from_another_location_is_refused(self) -> None:
        service, _repo, _i, org, location, session_id = self._setup(
            session_location=uuid.uuid4()
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_redirect_naming_a_foreign_site_is_refused(self) -> None:
        service, repo, _i, org, location, session_id = self._setup()
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="somebody-elses-site",
            )
        # Recorded server-side even though the response is opaque.
        assert any(e.status == "error" for e in repo.events)

    async def test_no_session_lookup_wired_refuses_rather_than_allows(self) -> None:
        """An unauthenticated endpoint whose one check is unavailable must
        not fall through to "allow"."""
        repo = FakeRepository()
        org, location = uuid.uuid4(), uuid.uuid4()
        repo.add(_integration(organization_id=org, location_id=location))
        service = _service(repo, guest_lookup=None)
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=uuid.uuid4(),
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_venue_with_no_integration_is_a_404(self) -> None:
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        lookup = FakeGuestSessionLookup(
            {session_id: FakeGuestSession(session_id, org, location)}
        )
        service = _service(FakeRepository(), guest_lookup=lookup)
        with pytest.raises(NetworkIntegrationNotFoundError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )

    async def test_a_failed_authorization_still_records_a_row(self) -> None:
        """A failed attempt is a row, not a silence -- it is what answers
        "did anything even try", the first question asked every time a
        guest says the WiFi did not work."""
        provider = FakeProvider(
            raise_on={"authorize_guest": ProviderTimeoutError()}
        )
        service, repo, _i, org, location, session_id = self._setup(
            provider=provider
        )
        with pytest.raises(ProviderTimeoutError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
                site="site-1",
            )
        assert len(repo.authorizations) == 1
        assert repo.authorizations[0].status == AuthorizationStatus.FAILED.value
        assert repo.authorizations[0].error_code == ErrorCode.TIMEOUT.value

    async def test_a_malformed_client_mac_is_refused(self) -> None:
        service, _repo, _i, org, location, session_id = self._setup()
        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="nope",
                site="site-1",
            )

    async def test_the_response_carries_no_credential(self) -> None:
        service, _repo, _i, org, location, session_id = self._setup()
        outcome = await service.authorize_portal_client(
            session_id=session_id,
            organization_id=org,
            location_id=location,
            provider="omada",
            client_mac="AA-BB-CC-DD-EE-FF",
            site="site-1",
        )
        assert "shh" not in str(outcome)


# ============================================================================
# CR-001: deauthorization is unsupported, honestly
# ============================================================================


class TestDeauthorizationIsUnsupported:
    """Contract change CR-001. Omada publishes no deauthorization endpoint.

    The assertion is that this platform *says so* rather than reporting a
    success it did not achieve -- the exact failure
    ``app.domains.guest_access.device_adapters`` was written to fix.
    """

    async def test_it_surfaces_api_unsupported_rather_than_faking_success(
        self,
    ) -> None:
        org, location = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        repo.add(_integration(organization_id=org, location_id=location))
        provider = FakeProvider(
            raise_on={"deauthorize_guest": ProviderUnsupportedApiError()}
        )
        service = _service(repo, provider=provider)
        with pytest.raises(
            NetworkIntegrationDeauthorizationUnsupportedError
        ) as caught:
            await service.deauthorize_portal_client(
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
            )
        assert caught.value.code is ErrorCode.API_UNSUPPORTED
        assert caught.value.status_code == 501

    async def test_the_message_does_not_claim_the_device_was_disconnected(
        self,
    ) -> None:
        error = NetworkIntegrationDeauthorizationUnsupportedError()
        assert "not disconnected" in error.message
        assert "cannot be ended on demand" in error.message

    async def test_nothing_is_recorded_as_deauthorized(self) -> None:
        """Recording a deauthorization this platform did not achieve would
        put the same falsehood in the database instead of the response."""
        org, location = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=location)
        )
        await repo.create_authorization(
            integration_id=integration.id,
            organization_id=org,
            location_id=location,
            guest_session_id=uuid.uuid4(),
            client_mac="AA:BB:CC:DD:EE:FF",
            status=AuthorizationStatus.AUTHORIZED.value,
            authorized_at=_now(),
        )
        provider = FakeProvider(
            raise_on={"deauthorize_guest": ProviderUnsupportedApiError()}
        )
        service = _service(repo, provider=provider)
        with pytest.raises(NetworkIntegrationDeauthorizationUnsupportedError):
            await service.deauthorize_portal_client(
                organization_id=org,
                location_id=location,
                provider="omada",
                client_mac="AA-BB-CC-DD-EE-FF",
            )
        assert (
            repo.authorizations[0].status == AuthorizationStatus.AUTHORIZED.value
        )
        assert repo.authorizations[0].deauthorized_at is None

    def test_the_session_duration_ceiling_reflects_the_missing_revocation(
        self,
    ) -> None:
        """With no deauthorization, the duration is the ONLY revocation
        mechanism, so the ceiling is a security control. 24 hours is the
        longest window in which "wait for it to expire" is a usable answer
        to "this guest is abusing the WiFi"."""
        assert MAX_SESSION_DURATION_SECONDS == 24 * 3600


# ============================================================================
# Sync, backoff, and the sweep
# ============================================================================


class TestSyncAndBackoff:
    async def test_a_successful_sync_caches_the_counts(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        # `location_id` is passed explicitly: `_integration()` defaults it
        # to None, which is a real half-configured state (the portal path
        # resolves an integration BY location, so a NULL one is never
        # selected for any venue) and now reports itself as such. This test
        # is about the fully-configured case.
        integration = repo.add(
            _integration(organization_id=org, location_id=uuid.uuid4())
        )
        service = _service(repo)
        outcome = await service.sync_integration(
            integration.id, requesting_organization_id=org
        )
        assert outcome.synced is True
        assert outcome.device_count == 2
        assert integration.provider_metadata["device_count"] == 2
        assert integration.last_sync_status == SyncStatus.OK.value
        assert integration.status == IntegrationStatus.CONNECTED.value
        assert integration.last_error_code is None
        assert integration.last_error_message is None

    async def test_a_sync_will_not_call_a_half_configured_venue_connected(
        self,
    ) -> None:
        """The defect this exists to end. Credentials work, `/api/info`
        answers, sites list -- and no site has been picked, so
        `authorize_portal_client` refuses every guest at the venue. Before
        this, all of that produced a green CONNECTED badge."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(
                organization_id=org,
                location_id=uuid.uuid4(),
                external_site_id=None,
            )
        )
        service = _service(repo)

        outcome = await service.sync_integration(
            integration.id, requesting_organization_id=org
        )

        assert integration.status == IntegrationStatus.UNCONFIGURED.value
        assert outcome.status == IntegrationStatus.UNCONFIGURED.value
        assert integration.last_error_code == ErrorCode.SETUP_INCOMPLETE.value
        assert "no controller site has been selected" in (
            integration.last_error_message or ""
        )

    async def test_the_message_says_what_it_costs_not_only_what_is_missing(
        self,
    ) -> None:
        """An operator ranking this against everything else on their screen
        needs the consequence, not the field name."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=None)
        )
        service = _service(repo)

        await service.sync_integration(
            integration.id, requesting_organization_id=org
        )

        message = integration.last_error_message or ""
        assert "cannot authorize any guest" in message
        assert "still have no internet" in message

    async def test_a_half_configured_venue_keeps_being_polled(self) -> None:
        """`last_sync_status` stays OK and the failure counter stays at
        zero, deliberately. Marking the sync itself failed would put the
        row into the backoff and stop polling it -- so the moment the
        operator finished the mapping, nothing would notice."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=None)
        )
        service = _service(repo)

        outcome = await service.sync_integration(
            integration.id, requesting_organization_id=org
        )

        assert outcome.synced is True
        assert integration.last_sync_status == SyncStatus.OK.value
        assert (
            integration.provider_metadata.get("consecutive_failure_count") == 0
        )

    async def test_the_events_feed_records_it_as_an_error(self) -> None:
        """The feed answers "what has this integration been doing". "It has
        been talking to the controller perfectly and authorizing nobody" is
        the most important thing it can say, and an OK row does not say
        it."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(organization_id=org, location_id=None)
        )
        service = _service(repo)

        await service.sync_integration(
            integration.id, requesting_organization_id=org
        )

        sync_events = [
            e
            for e in repo.events
            if e.event_type == IntegrationEventType.SYNC.value
        ]
        assert len(sync_events) == 1
        assert sync_events[0].status == IntegrationEventStatus.ERROR.value
        assert sync_events[0].error_code == ErrorCode.SETUP_INCOMPLETE.value

    async def test_finishing_the_setup_clears_it_on_the_next_sync(self) -> None:
        """The state has to be able to leave, not only arrive."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(
                organization_id=org, location_id=uuid.uuid4(), external_site_id=None
            )
        )
        service = _service(repo)
        await service.sync_integration(
            integration.id, requesting_organization_id=org
        )
        assert integration.status == IntegrationStatus.UNCONFIGURED.value

        integration.external_site_id = "site-1"
        await service.sync_integration(
            integration.id, requesting_organization_id=org
        )

        assert integration.status == IntegrationStatus.CONNECTED.value
        assert integration.last_error_code is None
        assert integration.last_error_at is None

    async def test_a_failed_sync_records_the_error_and_increments_the_counter(
        self,
    ) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        provider = FakeProvider(
            raise_on={"get_controller_info": ProviderTimeoutError()}
        )
        service = _service(repo, provider=provider)
        outcome = await service.sync_integration(
            integration.id, requesting_organization_id=org
        )
        assert outcome.synced is False
        assert integration.last_sync_status == SyncStatus.ERROR.value
        assert integration.provider_metadata["consecutive_failure_count"] == 1
        assert any(e.status == "error" for e in repo.events)

    def test_the_backoff_doubles_and_is_capped(self) -> None:
        service = _service()
        integration = _integration(sync_interval_seconds=300)
        integration.provider_metadata = {}
        assert service._effective_sync_interval(integration) == 300
        integration.provider_metadata = {"consecutive_failure_count": 1}
        assert service._effective_sync_interval(integration) == 600
        integration.provider_metadata = {"consecutive_failure_count": 3}
        assert service._effective_sync_interval(integration) == 2400
        # Capped rather than unbounded: an uncapped exponential eventually
        # means "we stopped checking", which is indistinguishable from a bug.
        integration.provider_metadata = {"consecutive_failure_count": 50}
        assert service._effective_sync_interval(integration) == 300 * 32

    def test_a_never_synced_integration_is_always_due(self) -> None:
        service = _service()
        assert service.is_sync_due(_integration(last_sync_at=None)) is True

    def test_a_recently_synced_integration_is_not_due(self) -> None:
        service = _service()
        integration = _integration(last_sync_at=_now() - timedelta(seconds=10))
        assert service.is_sync_due(integration) is False

    def test_a_disabled_integration_is_never_due(self) -> None:
        service = _service()
        integration = _integration(is_enabled=False, last_sync_at=None)
        assert service.is_sync_due(integration) is False

    def test_a_soft_deleted_integration_is_never_due(self) -> None:
        service = _service()
        integration = _integration(last_sync_at=None)
        integration.is_deleted = True
        assert service.is_sync_due(integration) is False

    def test_backoff_defers_a_row_whose_base_interval_has_elapsed(self) -> None:
        """The SQL selects on the base interval; this is the re-check that
        applies the JSONB-derived multiplier."""
        service = _service()
        integration = _integration(
            sync_interval_seconds=300,
            last_sync_at=_now() - timedelta(seconds=400),
            provider_metadata={"consecutive_failure_count": 3},
        )
        assert service.is_sync_due(integration) is False

    async def test_the_sweep_syncs_due_integrations(self) -> None:
        repo = FakeRepository()
        repo.add(_integration(last_sync_at=None))
        repo.add(_integration(last_sync_at=None))
        service = _service(repo)
        summary = await run_network_integration_sync_sweep(service, limit=50)
        assert summary.considered == 2
        assert summary.synced == 2
        assert summary.errors == 0

    async def test_the_sweep_skips_a_backed_off_integration(self) -> None:
        repo = FakeRepository()
        repo.add(
            _integration(
                last_sync_at=_now() - timedelta(seconds=400),
                provider_metadata={"consecutive_failure_count": 5},
            )
        )
        service = _service(repo)
        summary = await run_network_integration_sync_sweep(service, limit=50)
        assert summary.skipped_backoff == 1
        assert summary.synced == 0

    async def test_one_tenants_failure_does_not_abort_the_sweep(self) -> None:
        """Per-integration isolation: one unreachable controller must not
        stop every other tenant being polled."""
        repo = FakeRepository()
        broken = repo.add(_integration(last_sync_at=None))
        repo.add(_integration(last_sync_at=None))

        provider = FakeProvider()
        original = provider.get_controller_info

        async def _selective(config):
            if config.controller_id == broken.controller_id and broken.name == "boom":
                raise ProviderTimeoutError()
            return await original(config)

        broken.name = "boom"
        service = _service(repo, provider=provider)
        summary = await run_network_integration_sync_sweep(service, limit=50)
        assert summary.considered == 2
        assert summary.synced + summary.errors == 2

    async def test_an_integration_with_no_credentials_is_not_a_failure(self) -> None:
        """Nobody has finished setting this up. Recording a sync failure
        would put a red badge on an abandoned wizard."""
        repo = FakeRepository()
        integration = repo.add(
            _integration(with_credentials=False, last_sync_at=None)
        )
        service = _service(repo)
        outcome = await service._sync(integration)
        assert outcome.synced is False
        assert outcome.error_code == ErrorCode.CREDENTIALS_REQUIRED.value
        assert integration.last_error_code is None


# ============================================================================
# Platform surface
# ============================================================================


class TestPlatformSurface:
    async def test_the_summary_aggregates_across_tenants(self) -> None:
        repo = FakeRepository()
        repo.add(_integration(organization_id=uuid.uuid4()))
        repo.add(_integration(organization_id=uuid.uuid4(), is_enabled=False))
        service = _service(repo)
        summary = await service.get_platform_summary()
        assert summary.tenant_count == 2
        assert summary.integration_count == 2
        assert summary.disabled_count == 1

    async def test_a_platform_operator_can_disable_any_tenants_integration(
        self,
    ) -> None:
        repo = FakeRepository()
        audit = FakeAuditWriter()
        integration = repo.add(_integration(organization_id=uuid.uuid4()))
        service = _service(repo, audit=audit)
        updated = await service.set_platform_enabled(
            integration.id, actor_user_id=uuid.uuid4(), is_enabled=False
        )
        assert updated.is_enabled is False
        assert updated.status == IntegrationStatus.DISABLED.value
        # The audit trail is what makes a deliberate cross-tenant write
        # defensible.
        assert any(
            e.get("metadata", e.get("event_metadata", {})).get("platform_action")
            for e in audit.entries
        )

    async def test_platform_enable_is_idempotent(self) -> None:
        repo = FakeRepository()
        integration = repo.add(_integration(is_enabled=True))
        service = _service(repo)
        result = await service.set_platform_enabled(
            integration.id, actor_user_id=None, is_enabled=True
        )
        assert result.status == IntegrationStatus.CONNECTED.value


# ============================================================================
# Audit
# ============================================================================


class TestAudit:
    async def test_every_lifecycle_action_writes_an_audit_entry(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        audit = FakeAuditWriter()
        service = _service(repo, audit=audit)

        integration = await service.create_integration(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            external_site_id="site-1",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="secret",
        )
        await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"name": "Renamed"},
        )
        await service.rotate_credentials(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            auth_mode="openapi",
            client_id="c2",
            client_secret="s2",
        )
        await service.test_integration_connection(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )
        await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"is_enabled": False},
        )
        await service.delete_integration(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )

        actions = [e["action"] for e in audit.entries]
        for expected in (
            "network_integration_connected",
            "network_integration_config_changed",
            "network_integration_credentials_rotated",
            "network_integration_test_connection",
            "network_integration_disabled",
            "network_integration_disconnected",
        ):
            assert expected in actions, f"missing audit action: {expected}"

    async def test_no_audit_entry_carries_a_secret(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        audit = FakeAuditWriter()
        service = _service(repo, audit=audit)
        await service.create_integration(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org,
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="TOP-SECRET-VALUE",
        )
        assert "TOP-SECRET-VALUE" not in str(audit.entries)

    async def test_events_are_written_for_the_operational_feed(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        service = _service(repo)
        integration = await service.create_integration(
            actor_user_id=None,
            requesting_organization_id=org,
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
        )
        assert len(repo.events) == 1
        assert repo.events[0].integration_id == integration.id
        assert repo.events[0].organization_id == org


# ============================================================================
# Provider seam
# ============================================================================


class TestProviderSeamIsolation:
    """The seam is the point of the whole design, so it is checked rather
    than trusted. A seam nobody verifies is a seam that closes."""

    def test_only_the_omada_module_imports_the_gateway(self) -> None:
        """Checked against the real import graph, not a substring sweep.

        This used to grep each file for ``wyfy_device_gateway`` and failed
        on every module whose *docstring* explains the seam -- which is
        most of them, since explaining the seam is the house style. A
        prose mention is not a dependency; an import is. Parsing the AST
        asks the question the seam actually cares about.
        """
        import ast
        import pathlib

        domain = pathlib.Path("app/domains/network_integration")
        offenders = []
        for path in sorted(domain.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            imported: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported += [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            if path.name != "omada.py" and any(
                m.split(".")[0] == "wyfy_device_gateway" for m in imported
            ):
                offenders.append(str(path))
        assert not offenders, (
            "these modules import the gateway, breaking the provider seam: "
            f"{offenders}. Only providers/omada.py may."
        )

    def test_the_service_module_names_no_vendor(self) -> None:
        """Same correction: identifiers, not prose.

        ``service.py`` is allowed -- encouraged -- to *explain* Omada in
        its docstrings. What it must never do is import the gateway or
        reference a vendor-specific symbol, because that is what would
        make a second provider a rewrite instead of a registration.
        """
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("app/domains/network_integration/service.py").read_text()
        )

        imported: list[str] = []
        identifiers: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            elif isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)

        assert not any(
            m.split(".")[0] == "wyfy_device_gateway" for m in imported
        ), f"service.py imports the gateway directly: {imported}"

        vendor_symbols = {"TpLink", "OmadaControllerAdapter", "OmadaClient"}
        assert not (identifiers & vendor_symbols), (
            "service.py references a vendor-specific symbol: "
            f"{sorted(identifiers & vendor_symbols)}"
        )

    def test_the_registry_resolves_the_omada_provider(self) -> None:
        from app.domains.network_integration.providers import (
            get_network_provider,
            list_supported_providers,
        )

        assert list_supported_providers() == ["omada"]
        provider = get_network_provider("omada")
        assert provider.kind == "omada"
        assert isinstance(provider, NetworkProvider)

    def test_an_unknown_provider_is_a_domain_error_not_a_keyerror(self) -> None:
        from app.domains.network_integration.exceptions import (
            UnsupportedNetworkProviderError,
        )
        from app.domains.network_integration.providers import get_network_provider

        with pytest.raises(UnsupportedNetworkProviderError):
            get_network_provider("ubiquiti")

    def test_the_fake_provider_satisfies_the_protocol(self) -> None:
        """If this fails, the fakes have drifted from the Protocol and every
        provider test above is testing a shape nothing implements."""
        assert isinstance(FakeProvider(), NetworkProvider)

    def test_every_gateway_error_code_maps_to_a_domain_exception(self) -> None:
        """All ten normalized codes from contract §2, so a controller
        failure can never escape as an unhandled 500."""
        expected = {
            "OMADA_AUTH_FAILED",
            "OMADA_CONNECTION_FAILED",
            "OMADA_TIMEOUT",
            "OMADA_RATE_LIMITED",
            "OMADA_INVALID_CONTROLLER",
            "OMADA_SITE_NOT_FOUND",
            "OMADA_CLIENT_NOT_FOUND",
            "OMADA_AUTHORIZATION_FAILED",
            "OMADA_API_UNSUPPORTED",
            "OMADA_SESSION_EXPIRED",
        }
        assert set(PROVIDER_ERRORS_BY_CODE) == expected
        for code, error_class in PROVIDER_ERRORS_BY_CODE.items():
            assert error_class().code.value == code

    def test_an_unmapped_gateway_code_degrades_to_connection_failed(self) -> None:
        """A wrong-but-safe classification beats an unhandled exception."""
        from app.domains.network_integration.providers.omada import _translate

        class _Weird(Exception):
            code = "OMADA_SOMETHING_NEW"

        translated = _translate(_Weird("upstream said no"))
        assert translated.code is ErrorCode.CONNECTION_FAILED

    def test_a_gateway_error_is_recognised_by_its_code_attribute(self) -> None:
        from app.domains.network_integration.providers.omada import _is_gateway_error

        class _WithCode(Exception):
            code = "OMADA_TIMEOUT"

        assert _is_gateway_error(_WithCode()) is True
        assert _is_gateway_error(ValueError("nope")) is False

    def test_the_domain_imports_with_the_gateway_absent(self) -> None:
        """The lazy import is what keeps this domain -- and therefore
        ``create_app()``, and therefore all 131 test modules -- independent
        of another repository's build state."""
        import importlib

        module = importlib.import_module(
            "app.domains.network_integration.providers.omada"
        )
        assert module.OmadaProvider().kind == "omada"


# ============================================================================
# Permission checks (structural)
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_customer_and_platform_route_is_permission_gated(self) -> None:
        offenders = []
        for route in integration_router.routes:
            names = {
                getattr(dep.call, "__qualname__", "")
                for dep in getattr(route, "dependant", None).dependencies
            }
            if not any(n.startswith("RequirePermission") for n in names):
                offenders.append(f"{sorted(route.methods)} {route.path}")
        assert not offenders, offenders

    def test_the_platform_routes_require_global_scope(self) -> None:
        """An Organization Owner holds ``network_integrations.read`` at
        ORGANIZATION scope. Without the explicit GLOBAL, the bare key
        would let a customer read every tenant's integrations."""
        from app.domains.rbac.enums import ScopeType

        platform_routes = [
            r for r in integration_router.routes if "/platform/" in r.path
        ]
        # summary, list, get, events, enable, disable, test-connection,
        # onboard. Asserted as a count rather than a set so that adding a
        # ninth platform route without a GLOBAL scope fails here loudly.
        assert len(platform_routes) == 8
        for route in platform_routes:
            scopes = []
            for dep in route.dependant.dependencies:
                closure = getattr(dep.call, "__closure__", None) or ()
                scopes.extend(
                    cell.cell_contents
                    for cell in closure
                    if isinstance(cell.cell_contents, ScopeType)
                )
            assert ScopeType.GLOBAL in scopes, f"{route.path} is not GLOBAL-scoped"

    def test_the_portal_route_is_deliberately_ungated(self) -> None:
        """A guest holds no roles, so there is no permission to check.
        Allowlisted with that reasoning in
        ``tests/unit/test_route_permission_coverage.py``."""
        assert len(portal_router.routes) == 1
        route = portal_router.routes[0]
        assert route.path == "/network-integrations/portal/authorize"
        names = {
            getattr(dep.call, "__qualname__", "")
            for dep in route.dependant.dependencies
        }
        assert not any(n.startswith("RequirePermission") for n in names)

    def test_the_permission_keys_used_are_all_seeded(self) -> None:
        from app.domains.rbac.enums import PermissionAction, PermissionModule
        from app.domains.rbac.seed import MODULE_ACTIONS, permission_key

        seeded = {
            permission_key(PermissionModule.NETWORK_INTEGRATIONS, action)
            for action in MODULE_ACTIONS[PermissionModule.NETWORK_INTEGRATIONS]
        }
        for action in ("read", "create", "update", "delete"):
            assert f"network_integrations.{action}" in seeded
        assert PermissionAction.READ in MODULE_ACTIONS[
            PermissionModule.NETWORK_INTEGRATIONS
        ]

    def test_the_module_is_location_scoped(self) -> None:
        from app.domains.rbac.enums import PermissionModule, ScopeType
        from app.domains.rbac.seed import (
            MODULE_DISPLAY_NAMES,
            MODULE_NARROWEST_SCOPE,
        )

        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.NETWORK_INTEGRATIONS]
            is ScopeType.LOCATION
        )
        assert MODULE_DISPLAY_NAMES[PermissionModule.NETWORK_INTEGRATIONS]

    def test_the_network_roles_hold_the_permission(self) -> None:
        """Same profile as NETWORK_DEVICE: the network roles get it, the
        guest-facing front-desk roles do not."""
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import SYSTEM_ROLES

        by_slug = {role.slug: role for role in SYSTEM_ROLES}
        for slug in ("network-administrator", "network-engineer"):
            grants = by_slug[slug].grants()
            assert PermissionModule.NETWORK_INTEGRATIONS in grants, slug
        for slug in ("reception-staff", "helpdesk", "guest-operator"):
            grants = by_slug[slug].grants()
            assert PermissionModule.NETWORK_INTEGRATIONS not in grants, slug

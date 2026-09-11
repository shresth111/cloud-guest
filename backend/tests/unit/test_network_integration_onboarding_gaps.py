"""Two ways an Omada venue could be set up "correctly" and still sign nobody in.

Both were found writing the operator runbook
(``docs/network_integration/OMADA_OPERATOR_RUNBOOK.md`` section 2) and both
are fixed here:

1. **An Open API integration could never authorize a guest.** The
   controller only authorizes guests through a hotspot *operator* login, in
   either auth mode, and the credential validator refused to store one on an
   Open API row. The dashboard recommended Open API. So the recommended setup
   synced green and turned every guest away with ``OMADA_API_UNSUPPORTED``.

2. **An integration created from the customer page never got a fleet row.**
   ``guest_sessions.router_id`` is NOT NULL, and only Master onboarding wrote
   the controller's fleet row, so a customer-created integration sat on
   ``fleet_device_missing`` forever, with no portal link and nothing its
   operator could do about it.

Helpers are imported from ``test_network_integration`` rather than copied,
so a change to what a "normal" integration row looks like there reaches
these tests too.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.network_integration.constants import (
    ControllerAuthMode,
    ErrorCode,
    IntegrationStatus,
    NetworkIntegrationAuditAction,
    PortalReadinessGap,
)
from app.domains.network_integration.crypto import (
    encrypt_credentials,
    stored_credential_fields,
)
from app.domains.network_integration.exceptions import (
    CrossOrganizationNetworkIntegrationAccessError,
    NetworkIntegrationLocationRequiredError,
    NetworkIntegrationNotFoundError,
    NetworkIntegrationUrlRejectedError,
)
from app.domains.network_integration.router import (
    create_integration as create_integration_route,
)
from app.domains.network_integration.router import (
    ensure_fleet_device as ensure_fleet_device_route,
)
from app.domains.network_integration.router import router as integration_router
from app.domains.network_integration.schemas import NetworkIntegrationCreateRequest
from app.domains.network_integration.validators import (
    describe_portal_readiness_gaps,
    portal_readiness_gaps,
)

from .test_network_integration import (
    CONTROLLER_URL,
    FakeAuditWriter,
    FakeFleetDeviceProvisioner,
    FakeRepository,
    _integration,
    _service,
)

# ============================================================================
# 1. An Open API integration needs the operator login for guest sign-in
# ============================================================================


class TestStoredCredentialFields:
    def test_it_returns_names_and_never_values(self) -> None:
        ciphertext = encrypt_credentials(
            {"client_id": "cid", "client_secret": "shh", "username": "op"}
        )
        fields = stored_credential_fields(ciphertext)
        assert fields == frozenset({"client_id", "client_secret", "username"})
        assert "shh" not in repr(fields)

    def test_nothing_stored_is_cannot_tell_not_empty(self) -> None:
        assert stored_credential_fields(None) is None
        assert stored_credential_fields("") is None

    def test_an_unreadable_ciphertext_is_cannot_tell_and_does_not_raise(self) -> None:
        assert stored_credential_fields("not-a-fernet-token") is None


class TestAnOpenApiIntegrationWithoutTheOperatorLoginIsNotReady:
    def test_the_app_alone_is_a_readiness_gap(self) -> None:
        app_only = _integration(
            location_id=uuid.uuid4(),
            router_id=uuid.uuid4(),
            with_guest_operator=False,
        )
        assert portal_readiness_gaps(app_only) == (
            PortalReadinessGap.GUEST_OPERATOR_MISSING,
        )

    def test_the_app_plus_the_operator_login_is_ready(self) -> None:
        both = _integration(location_id=uuid.uuid4(), router_id=uuid.uuid4())
        assert portal_readiness_gaps(both) == ()

    def test_a_legacy_row_is_not_asked_for_it_twice(self) -> None:
        legacy = _integration(
            location_id=uuid.uuid4(),
            router_id=uuid.uuid4(),
            auth_mode=ControllerAuthMode.LEGACY.value,
            credentials_encrypted=encrypt_credentials(
                {"username": "op", "password": "pw"}
            ),
        )
        assert portal_readiness_gaps(legacy) == ()

    def test_an_unreadable_ciphertext_does_not_invent_a_missing_account(self) -> None:
        """A key-management fault is reported on its own path; naming a
        missing operator account over it would send somebody to create an
        account that may already be stored."""
        unreadable = _integration(
            location_id=uuid.uuid4(),
            router_id=uuid.uuid4(),
            credentials_encrypted="not-a-fernet-token",
        )
        assert PortalReadinessGap.GUEST_OPERATOR_MISSING not in portal_readiness_gaps(
            unreadable
        )

    def test_the_sentence_names_the_account_and_the_cost(self) -> None:
        sentence = describe_portal_readiness_gaps(
            (PortalReadinessGap.GUEST_OPERATOR_MISSING,)
        )
        assert "hotspot operator account" in sentence
        assert "cannot authorize any guest" in sentence

    async def test_the_sync_no_longer_calls_it_connected(self) -> None:
        """Before: the Open API app worked, so the sync set CONNECTED over a
        venue that turned every guest away."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(
                organization_id=org,
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
                with_guest_operator=False,
            )
        )
        outcome = await _service(repo).sync_integration(
            integration.id, requesting_organization_id=org
        )
        assert outcome.synced is True
        assert integration.status == IntegrationStatus.UNCONFIGURED.value
        assert outcome.error_code == ErrorCode.SETUP_INCOMPLETE.value
        assert "hotspot operator account" in (outcome.message or "")

    async def test_an_open_api_row_can_be_created_with_the_operator_login(self) -> None:
        repo = FakeRepository()
        integration = await _service(repo).create_integration(
            actor_user_id=None,
            requesting_organization_id=uuid.uuid4(),
            provider="omada",
            name="Lobby",
            base_url=CONTROLLER_URL,
            auth_mode="openapi",
            external_site_id="site-1",
            session_duration_seconds=3600,
            sync_interval_seconds=300,
            client_id="cid",
            client_secret="secret",
            username="operator",
            password="pw",
        )
        assert stored_credential_fields(integration.credentials_encrypted) == frozenset(
            {"client_id", "client_secret", "username", "password"}
        )
        assert PortalReadinessGap.GUEST_OPERATOR_MISSING not in portal_readiness_gaps(
            integration
        )

    async def test_half_an_operator_login_is_refused_at_rotation(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(_integration(organization_id=org))
        with pytest.raises(NetworkIntegrationUrlRejectedError, match="both its name"):
            await _service(repo).rotate_credentials(
                integration.id,
                actor_user_id=None,
                requesting_organization_id=org,
                auth_mode="openapi",
                client_id="cid",
                client_secret="secret",
                username="operator",
            )

    async def test_rotating_in_the_operator_login_clears_the_gap(self) -> None:
        """How an existing app-only integration is repaired: replace the
        credentials with the app plus the operator login."""
        org = uuid.uuid4()
        repo = FakeRepository()
        integration = repo.add(
            _integration(
                organization_id=org,
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
                with_guest_operator=False,
            )
        )
        assert portal_readiness_gaps(integration)

        await _service(repo).rotate_credentials(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            auth_mode="openapi",
            client_id="cid",
            client_secret="secret",
            username="operator",
            password="pw",
        )
        assert portal_readiness_gaps(integration) == ()


# ============================================================================
# 2. The customer path registers the fleet device
# ============================================================================


class TestEnsureFleetDevice:
    async def test_a_mapped_fleetless_integration_gets_its_fleet_row(self) -> None:
        org, location = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        audit = FakeAuditWriter()
        integration = repo.add(
            _integration(organization_id=org, location_id=location, router_id=None)
        )

        result = await _service(
            repo, fleet_provisioner=provisioner, audit=audit
        ).ensure_fleet_device(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )

        assert len(provisioner.calls) == 1
        call = provisioner.calls[0]
        assert call["location_id"] == location
        assert call["requesting_organization_id"] == org
        # Never the router domain's `mikrotik` default.
        assert call["vendor"] == "tplink_omada"
        # Nobody on this path was asked for a model; the provider's generic
        # one lands in the NOT NULL column instead of an invented plate.
        assert call["model"] == "Omada Controller"
        # Synthetic, locally administered -- the same identity Master
        # onboarding generates for a software controller.
        assert call["settings"]["synthetic_identity"] is True
        assert call["serial_number"].startswith("OMADA-")
        assert int(call["mac_address"].split(":")[0], 16) & 0b10
        assert result.router_id is not None
        assert PortalReadinessGap.FLEET_DEVICE_MISSING not in portal_readiness_gaps(
            result
        )
        assert [
            entry["action"]
            for entry in audit.entries
            if entry["action"]
            == NetworkIntegrationAuditAction.FLEET_DEVICE_ONBOARDED.value
        ]

    async def test_it_is_idempotent(self) -> None:
        org = uuid.uuid4()
        existing_router = uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(
                organization_id=org,
                location_id=uuid.uuid4(),
                router_id=existing_router,
            )
        )

        service = _service(repo, fleet_provisioner=provisioner)
        result = await service.ensure_fleet_device(
            integration.id, actor_user_id=None, requesting_organization_id=org
        )

        assert provisioner.calls == []
        assert result.router_id == existing_router

    async def test_an_unmapped_integration_is_told_to_pick_a_venue(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(organization_id=org, location_id=None, router_id=None)
        )

        with pytest.raises(NetworkIntegrationLocationRequiredError) as caught:
            await _service(repo, fleet_provisioner=provisioner).ensure_fleet_device(
                integration.id, actor_user_id=None, requesting_organization_id=org
            )

        assert caught.value.code == ErrorCode.LOCATION_REQUIRED
        assert provisioner.calls == []

    async def test_another_tenants_integration_is_not_reachable(self) -> None:
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(organization_id=uuid.uuid4(), location_id=uuid.uuid4())
        )

        with pytest.raises(
            (
                CrossOrganizationNetworkIntegrationAccessError,
                NetworkIntegrationNotFoundError,
            )
        ):
            await _service(repo, fleet_provisioner=provisioner).ensure_fleet_device(
                integration.id,
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )
        assert provisioner.calls == []


class TestMappingAVenueRegistersTheFleetDevice:
    async def test_mapping_a_location_writes_the_fleet_row(self) -> None:
        """"Finish setup" used to end on a gap its operator could not clear."""
        org, location = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(organization_id=org, location_id=None, router_id=None)
        )

        service = _service(repo, fleet_provisioner=provisioner)
        updated = await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"location_id": location},
        )

        assert len(provisioner.calls) == 1
        assert provisioner.calls[0]["location_id"] == location
        assert updated.router_id is not None
        assert portal_readiness_gaps(updated) == ()

    async def test_an_edit_that_does_not_map_a_venue_writes_nothing(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(organization_id=org, location_id=None, router_id=None)
        )

        await _service(repo, fleet_provisioner=provisioner).update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"name": "Renamed"},
        )

        assert provisioner.calls == []

    async def test_a_row_that_already_has_a_fleet_device_is_not_given_a_second(
        self,
    ) -> None:
        org = uuid.uuid4()
        existing_router = uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(
                organization_id=org,
                location_id=uuid.uuid4(),
                router_id=existing_router,
            )
        )

        service = _service(repo, fleet_provisioner=provisioner)
        updated = await service.update_integration(
            integration.id,
            actor_user_id=None,
            requesting_organization_id=org,
            fields={"location_id": uuid.uuid4()},
        )

        assert provisioner.calls == []
        assert updated.router_id == existing_router


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="req-1"))


class TestTheCustomerRoutes:
    """The route handlers, called directly with a real service over the
    in-memory fakes -- the hop where "and then register the fleet row" is
    most easily forgotten is the route, not the service."""

    def _payload(self, **overrides: object) -> NetworkIntegrationCreateRequest:
        body: dict[str, object] = {
            "name": "Lobby",
            "base_url": CONTROLLER_URL,
            "auth_mode": "openapi",
            "client_id": "cid",
            "client_secret": "secret",
            "username": "operator",
            "password": "pw",
            "external_site_id": "site-1",
        }
        body.update(overrides)
        return NetworkIntegrationCreateRequest.model_validate(body)

    async def test_creating_with_a_venue_writes_the_fleet_row_too(self) -> None:
        org, location = uuid.uuid4(), uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(repo, fleet_provisioner=provisioner)

        response = await create_integration_route(
            request=_request(),
            payload=self._payload(location_id=str(location)),
            actor=None,
            requesting_organization_id=org,
            service=service,
        )

        assert len(provisioner.calls) == 1
        assert "fleet_device_missing" not in response["data"]["portal_readiness_gaps"]
        assert response["data"]["portal_url_host_and_query"]
        (stored,) = repo.integrations.values()
        assert stored.router_id is not None

    async def test_creating_without_a_venue_writes_no_fleet_row(self) -> None:
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        service = _service(repo, fleet_provisioner=provisioner)

        await create_integration_route(
            request=_request(),
            payload=self._payload(),
            actor=None,
            requesting_organization_id=uuid.uuid4(),
            service=service,
        )

        assert provisioner.calls == []

    async def test_the_repair_route_registers_a_stuck_integration(self) -> None:
        org = uuid.uuid4()
        repo = FakeRepository()
        provisioner = FakeFleetDeviceProvisioner()
        integration = repo.add(
            _integration(organization_id=org, location_id=uuid.uuid4(), router_id=None)
        )

        await ensure_fleet_device_route(
            request=_request(),
            integration_id=integration.id,
            actor=None,
            requesting_organization_id=org,
            service=_service(repo, fleet_provisioner=provisioner),
        )

        assert len(provisioner.calls) == 1
        assert integration.router_id is not None

    def test_the_repair_route_needs_the_update_permission(self) -> None:
        (route,) = [
            r
            for r in integration_router.routes
            if r.path.endswith("/{integration_id}/fleet-device")
        ]
        assert route.methods == {"POST"}
        closures = [
            cell.cell_contents
            for dep in route.dependant.dependencies
            for cell in (getattr(dep.call, "__closure__", None) or ())
        ]
        assert "network_integrations.update" in closures

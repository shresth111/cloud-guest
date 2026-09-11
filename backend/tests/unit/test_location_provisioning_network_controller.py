"""Smart Location Provisioning with a network controller as the first device.

A new customer whose venue has only a TP-Link Omada controller -- no
MikroTik anywhere -- used to be impossible to provision: the wizard and
``ProvisionLocationRequest`` both demanded a router serial and MAC, and the
only way through was to invent them. That MAC is a join key for client
lookups, MAC authorization and DHCP leases, so a fabricated one can collide
with a real device; #203 forbids it.

The request now carries exactly one of ``router`` and
``network_controller``. The controller branch is Master onboarding's own
``create_integration_with_fleet_device`` pointed at the organization and
location the same request just created, in the same transaction.

These tests drive the REAL ``NetworkIntegrationService`` (backed by the
in-memory fakes ``test_network_integration`` already maintains), not a
stand-in for it -- the point being proven is that provisioning reuses that
service's validation, encryption guard and fleet-identity rules rather than
restating them. Helpers are imported from the two existing suites rather
than copied, so a change to either domain's fakes reaches these tests too.
"""

from __future__ import annotations

import dataclasses
import inspect
import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.domains.location.provisioning_dependencies import (
    get_location_provisioning_service,
)
from app.domains.location.provisioning_schemas import (
    NetworkControllerInputSchema,
    ProvisionLocationRequest,
)
from app.domains.location.provisioning_service import (
    NetworkControllerInput,
    NetworkControllerProvisioningUnavailableError,
    ProvisionLocationInput,
)
from app.domains.location.router import _require_controller_permission
from app.domains.network_integration.dependencies import (
    get_network_integration_service,
)
from app.domains.network_integration.exceptions import (
    NetworkIntegrationEncryptionKeyNotConfiguredError,
    NetworkIntegrationUrlRejectedError,
)
from app.domains.network_integration.schemas import (
    ControllerOnboardFields,
    PlatformOnboardRequest,
)
from app.domains.network_integration.service import NetworkIntegrationService
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError

from .test_location_provisioning import (
    _input,
    _new_org,
    make_service,
    run_within_transaction,
)
from .test_network_integration import (
    CONTROLLER_URL,
    FakeFleetDeviceProvisioner,
    FakeRepository,
    _service,
)

PROD_DEFAULT_KEY = Settings(environment="production")


# ============================================================================
# Harness
# ============================================================================


class RecordingControllerService:
    """Wraps the real ``NetworkIntegrationService`` so its two calls land in
    the provisioning fakes' shared call log and flush the shared fake
    session, exactly as every other composed step does. Everything else is
    delegated untouched -- the behaviour under test is the real service's."""

    def __init__(self, real: NetworkIntegrationService, fakes) -> None:
        self.real = real
        self.fakes = fakes

    async def precheck_controller_onboarding(self, **kwargs):
        self.fakes.calls.append("network_integration.precheck")
        return await self.real.precheck_controller_onboarding(**kwargs)

    async def create_integration_with_fleet_device(self, **kwargs):
        result = await self.real.create_integration_with_fleet_device(**kwargs)
        self.fakes.session.flush("network_integration.onboard")
        self.fakes.calls.append("network_integration.onboard")
        return result


def make_controller_service(
    *,
    settings: Settings | None = None,
    fleet_raises: Exception | None = None,
    wire_service: bool = True,
):
    """``make_service`` from the provisioning suite, plus a real
    ``NetworkIntegrationService`` wired in as ``network_controller_service``.
    Returns ``(service, fakes, base_plan_id, repository, fleet)``."""
    service, fakes, base_plan_id = make_service()
    repository = FakeRepository()
    fleet = FakeFleetDeviceProvisioner(raise_on_create=fleet_raises)
    real = _service(repository, fleet_provisioner=fleet, settings=settings)
    if wire_service:
        service.network_controller_service = RecordingControllerService(real, fakes)
    return service, fakes, base_plan_id, repository, fleet


def _controller(**overrides: object) -> NetworkControllerInput:
    fields: dict[str, object] = {
        "name": "Lobby Controller",
        "base_url": CONTROLLER_URL,
        "controller_model": "Omada Software Controller",
        "auth_mode": "legacy",
        "username": "hotspot-operator",
        "password": "operator-password",
        "external_site_id": "Default",
        "guest_ssid_name": "Guest WiFi",
    }
    fields.update(overrides)
    return NetworkControllerInput(**fields)  # type: ignore[arg-type]


def _controller_input(
    plan_id: uuid.UUID, controller: NetworkControllerInput | None = None
) -> ProvisionLocationInput:
    return dataclasses.replace(
        _input(new_organization=_new_org(), plan_id=plan_id),
        router=None,
        network_controller=controller or _controller(),
    )


def _location_counter_value(service) -> int:
    counter = service.location_service.location_code_counter
    return sum(counter.counters.values())


_LOCATION = {
    "name": "Downtown",
    "slug": "downtown",
    "address_line1": "1 Plaza Way",
    "city": "Austin",
    "state_province": "TX",
    "postal_code": "78701",
    "country": "US",
}
_OWNER = {"first_name": "Priya", "last_name": "Shah", "email": "priya@example.com"}
_ROUTER = {
    "name": "Lobby Router",
    "serial_number": "SN-00001",
    "mac_address": "AA:BB:CC:DD:EE:01",
    "model": "RB5009",
}
_CONTROLLER = {
    "name": "Lobby Controller",
    "base_url": CONTROLLER_URL,
    "controller_model": "Omada Software Controller",
    "auth_mode": "legacy",
    "username": "op",
    "password": "pw",
}


def _request(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "new_organization": {
            "name": "Grand Plaza",
            "slug": "grand-plaza",
            "contact_email": "ops@grandplaza.example.com",
        },
        "location": _LOCATION,
        "owner": _OWNER,
        "plan_id": str(uuid.uuid4()),
    }
    body.update(overrides)
    return body


# ============================================================================
# 1. Request shape: exactly one first device
# ============================================================================


class TestRequestSchema:
    def test_a_router_alone_is_still_accepted(self) -> None:
        request = ProvisionLocationRequest.model_validate(_request(router=_ROUTER))
        assert request.router is not None
        assert request.network_controller is None

    def test_a_controller_alone_is_accepted_without_serial_or_mac(self) -> None:
        request = ProvisionLocationRequest.model_validate(
            _request(network_controller=_CONTROLLER)
        )
        assert request.router is None
        assert request.network_controller is not None
        assert request.network_controller.serial_number is None
        assert request.network_controller.mac_address is None

    def test_neither_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="Exactly one of router"):
            ProvisionLocationRequest.model_validate(_request())

    def test_both_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="Exactly one of router"):
            ProvisionLocationRequest.model_validate(
                _request(router=_ROUTER, network_controller=_CONTROLLER)
            )

    def test_a_config_template_cannot_be_asked_for_a_controller(self) -> None:
        with pytest.raises(ValidationError, match="applies only to a MikroTik"):
            ProvisionLocationRequest.model_validate(
                _request(
                    network_controller=_CONTROLLER,
                    router_config_template_id=str(uuid.uuid4()),
                )
            )

    def test_half_a_hardware_identity_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="together"):
            ProvisionLocationRequest.model_validate(
                _request(network_controller={**_CONTROLLER, "serial_number": "SN-1"})
            )

    def test_the_controller_block_is_master_onboardings_own_model(self) -> None:
        """One description of a controller, shared -- so the two paths that
        register one cannot disagree about a field's bounds or
        requiredness."""
        assert issubclass(NetworkControllerInputSchema, ControllerOnboardFields)
        assert issubclass(PlatformOnboardRequest, ControllerOnboardFields)
        onboard_only = set(PlatformOnboardRequest.model_fields) - set(
            NetworkControllerInputSchema.model_fields
        )
        assert onboard_only == {"organization_id", "location_id"}


# ============================================================================
# 2. The MikroTik path is unchanged
# ============================================================================


class TestRouterPathUnchanged:
    async def test_router_provisioning_needs_no_network_integration_service(
        self,
    ) -> None:
        service, fakes, base_plan_id = make_service()
        assert service.network_controller_service is None

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )

        assert result.device_kind == "router"
        assert result.network_integration_id is None
        assert result.tunnel_ip_address == "10.100.0.5"
        assert "router_provisioning.assign_profile" in fakes.calls
        assert "wireguard.allocate_tunnel_via_hub" in fakes.calls

    async def test_the_audit_entry_says_which_kind_of_device(self) -> None:
        service, fakes, base_plan_id = make_service()
        await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )
        entry = next(
            e
            for e in fakes.audit_entries
            if e["action"] == AuditAction.LOCATION_PROVISIONED.value
        )
        assert entry["event_metadata"]["device_kind"] == "router"
        assert entry["event_metadata"]["network_integration_id"] is None


# ============================================================================
# 3. The controller path creates everything, in one transaction
# ============================================================================


class TestControllerPath:
    async def test_provisions_the_whole_venue_around_the_controller(self) -> None:
        service, fakes, base_plan_id, repository, fleet = make_controller_service()

        result = await run_within_transaction(
            fakes.session,
            service.provision_location(
                actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
            ),
        )

        expected_order = [
            "network_integration.precheck",
            "organization.create",
            "user.create",
            "network_integration.onboard",
            "subscription.create",
            "captive_portal.create_config",
            "audit:location_provisioned",
            "email.send",
        ]
        positions = [fakes.calls.index(step) for step in expected_order]
        assert positions == sorted(positions), f"steps out of order: {fakes.calls}"
        assert fakes.session.committed is True

        # One integration, at the venue this request created, for the
        # organization this request created.
        [integration] = repository.integrations.values()
        assert integration.location_id == result.location_id
        assert integration.organization_id == result.organization_id
        assert integration.auth_mode == "legacy"
        assert integration.external_site_id == "Default"
        assert integration.credentials_encrypted  # stored, encrypted
        assert "operator-password" not in integration.credentials_encrypted

        # ...and one fleet row, linked to it, carrying the controller's
        # vendor rather than the column's MikroTik default.
        [fleet_call] = fleet.calls
        assert fleet_call["location_id"] == result.location_id
        assert fleet_call["requesting_organization_id"] == result.organization_id
        assert fleet_call["vendor"] == "tplink_omada"
        assert integration.router_id == result.router_id

        assert result.device_kind == "network_controller"
        assert result.network_integration_id == integration.id
        assert result.router_name == "Lobby Controller"

    async def test_a_software_controller_gets_a_locally_administered_mac(
        self,
    ) -> None:
        """Never a plausible vendor MAC: the locally-administered bit is set,
        which no manufacturer may burn into hardware, so the generated
        identity cannot collide with a real access point."""
        service, fakes, base_plan_id, _, fleet = make_controller_service()
        await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
        )
        [fleet_call] = fleet.calls
        first_octet = int(fleet_call["mac_address"].split(":")[0], 16)
        assert first_octet & 0b10, "locally-administered bit must be set"
        assert not first_octet & 0b01, "must not be a multicast address"
        assert fleet_call["settings"]["synthetic_identity"] is True

    async def test_a_hardware_controller_keeps_its_label_identity(self) -> None:
        service, fakes, base_plan_id, _, fleet = make_controller_service()
        controller = _controller(
            controller_model="OC200",
            serial_number="Y2330A000001",
            mac_address="50:91:E3:00:00:01",
        )
        await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_controller_input(base_plan_id, controller),
        )
        [fleet_call] = fleet.calls
        assert fleet_call["serial_number"] == "Y2330A000001"
        assert fleet_call["mac_address"] == "50:91:E3:00:00:01"
        assert fleet_call["model"] == "OC200"

    async def test_no_routeros_template_and_no_wireguard_tunnel(self) -> None:
        """A config template is RouterOS script and a hub peer is the one
        write nothing can undo; a controller's fleet row can use neither."""
        service, fakes, base_plan_id, _, _ = make_controller_service()
        # No system template exists at all -- a router request would fail
        # with DefaultConfigTemplateNotFoundError; a controller must not.
        fakes.system_templates.clear()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
        )

        assert "router_provisioning.list_templates" not in fakes.calls
        assert "router_provisioning.assign_profile" not in fakes.calls
        assert "wireguard.allocate_tunnel_via_hub" not in fakes.calls
        assert "router.create" not in fakes.calls
        assert result.tunnel_ip_address is None

    async def test_the_audit_entry_names_the_integration(self) -> None:
        service, fakes, base_plan_id, repository, _ = make_controller_service()
        result = await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
        )
        entry = next(
            e
            for e in fakes.audit_entries
            if e["action"] == AuditAction.LOCATION_PROVISIONED.value
        )
        assert entry["event_metadata"]["device_kind"] == "network_controller"
        assert entry["event_metadata"]["network_integration_id"] == str(
            result.network_integration_id
        )


# ============================================================================
# 4. Failure leaves nothing half-created
# ============================================================================


class TestControllerFailures:
    async def test_a_fleet_registration_failure_rolls_the_customer_back(
        self,
    ) -> None:
        service, fakes, base_plan_id, _, _ = make_controller_service(
            fleet_raises=RuntimeError("duplicate serial")
        )

        with pytest.raises(RuntimeError, match="duplicate serial"):
            await run_within_transaction(
                fakes.session,
                service.provision_location(
                    actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
                ),
            )

        assert fakes.session.rolled_back is True
        assert fakes.session.committed is False
        assert "subscription.create" not in fakes.calls
        assert "captive_portal.create_config" not in fakes.calls
        assert "email.send" not in fakes.calls

    async def test_the_public_default_key_refuses_before_anything_is_created(
        self,
    ) -> None:
        """#224's refusal, reached through provisioning: outside local,
        controller credentials may not be encrypted under a key published
        in this repository. It fires in the precheck -- before the
        organization, before the owner, and before a location code is drawn
        from a counter a rollback does not give back."""
        service, fakes, base_plan_id, repository, fleet = make_controller_service(
            settings=PROD_DEFAULT_KEY
        )

        with pytest.raises(NetworkIntegrationEncryptionKeyNotConfiguredError) as exc:
            await service.provision_location(
                actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
            )

        assert exc.value.status_code == 503
        assert "organization.create" not in fakes.calls
        assert "user.create" not in fakes.calls
        assert fakes.session.flushed == []
        assert _location_counter_value(service) == 0
        assert repository.integrations == {}
        assert fleet.calls == []

    async def test_an_unacceptable_controller_url_refuses_first(self) -> None:
        service, fakes, base_plan_id, repository, _ = make_controller_service()
        controller = _controller(base_url="https://controller.example.com:9999")

        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_controller_input(base_plan_id, controller),
            )

        assert "organization.create" not in fakes.calls
        assert _location_counter_value(service) == 0
        assert repository.integrations == {}

    async def test_credentials_that_do_not_fit_the_mode_refuse_first(self) -> None:
        service, fakes, base_plan_id, repository, _ = make_controller_service()
        controller = _controller(auth_mode="legacy", username=None, password=None)
        controller = dataclasses.replace(controller, client_id="cid")

        with pytest.raises(NetworkIntegrationUrlRejectedError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_controller_input(base_plan_id, controller),
            )
        assert "organization.create" not in fakes.calls

    async def test_an_unwired_service_refuses_rather_than_provisioning_no_device(
        self,
    ) -> None:
        service, fakes, base_plan_id, _, _ = make_controller_service(
            wire_service=False
        )

        with pytest.raises(NetworkControllerProvisioningUnavailableError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(), data=_controller_input(base_plan_id)
            )
        assert "organization.create" not in fakes.calls

    async def test_a_hand_built_input_with_both_devices_is_refused(self) -> None:
        service, fakes, base_plan_id, _, _ = make_controller_service()
        both = dataclasses.replace(
            _input(new_organization=_new_org(), plan_id=base_plan_id),
            network_controller=_controller(),
        )
        with pytest.raises(ValueError, match="Exactly one of router"):
            await service.provision_location(actor_user_id=uuid.uuid4(), data=both)
        assert fakes.calls == []


# ============================================================================
# 5. The preview agrees with the real submit
# ============================================================================


class TestControllerPreview:
    async def test_preview_creates_nothing_and_needs_no_template(self) -> None:
        service, fakes, base_plan_id, repository, fleet = make_controller_service()
        fakes.system_templates.clear()

        preview = await service.preview_provision_location(
            data=_controller_input(base_plan_id)
        )

        assert preview.device_kind == "network_controller"
        assert preview.router_name == "Lobby Controller"
        # A software controller's identity is generated at provisioning
        # time; there is nothing honest to preview.
        assert preview.controller_id is None
        assert repository.integrations == {}
        assert fleet.calls == []
        assert fakes.session.flushed == []

    async def test_preview_shows_a_hardware_controllers_serial(self) -> None:
        service, _, base_plan_id, _, _ = make_controller_service()
        controller = _controller(
            serial_number="Y2330A000001", mac_address="50:91:E3:00:00:01"
        )
        preview = await service.preview_provision_location(
            data=_controller_input(base_plan_id, controller)
        )
        assert preview.controller_id == "Y2330A000001"

    async def test_preview_reports_the_same_default_key_refusal(self) -> None:
        service, _, base_plan_id, _, _ = make_controller_service(
            settings=PROD_DEFAULT_KEY
        )
        with pytest.raises(NetworkIntegrationEncryptionKeyNotConfiguredError):
            await service.preview_provision_location(
                data=_controller_input(base_plan_id)
            )


# ============================================================================
# 6. Permission: a controller is a network integration
# ============================================================================


class FakeAccessValidator:
    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.checks: list[tuple[uuid.UUID, str, ScopeType]] = []

    async def check(self, user_id, permission_key, *, scope_type, scope_context=None):
        self.checks.append((user_id, permission_key, scope_type))
        if not self.allow:
            raise PermissionDeniedError(permission_key)


class TestControllerPermission:
    USER = SimpleNamespace(id=str(uuid.uuid4()))

    async def test_a_controller_request_needs_network_integrations_create(
        self,
    ) -> None:
        validator = FakeAccessValidator()
        payload = ProvisionLocationRequest.model_validate(
            _request(network_controller=_CONTROLLER)
        )
        await _require_controller_permission(payload, self.USER, validator)
        assert validator.checks == [
            (uuid.UUID(self.USER.id), "network_integrations.create", ScopeType.GLOBAL)
        ]

    async def test_without_it_the_request_is_refused(self) -> None:
        payload = ProvisionLocationRequest.model_validate(
            _request(network_controller=_CONTROLLER)
        )
        with pytest.raises(PermissionDeniedError):
            await _require_controller_permission(
                payload, self.USER, FakeAccessValidator(allow=False)
            )

    async def test_a_router_request_needs_nothing_new(self) -> None:
        validator = FakeAccessValidator(allow=False)
        payload = ProvisionLocationRequest.model_validate(_request(router=_ROUTER))
        await _require_controller_permission(payload, self.USER, validator)
        assert validator.checks == []

    def test_production_wiring_supplies_the_network_integration_service(
        self,
    ) -> None:
        """The dependency, not a hand-built service, is what production
        uses -- so the controller branch is reachable there."""
        parameter = inspect.signature(get_location_provisioning_service).parameters[
            "network_integration_service"
        ]
        assert parameter.default.dependency is get_network_integration_service

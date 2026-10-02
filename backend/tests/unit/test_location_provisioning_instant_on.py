"""The Add Customer wizard's Aruba Instant On option (PM_SPEC §5 Wave 2).

``POST /locations/provision`` with ``instant_on_site`` creates the customer,
location, owner and ONE NAS-only ``aruba_instant_on`` fleet row in a single
transaction. What is pinned:

1. exactly one Aruba row, created by the REAL ``RouterService
   .create_nas_only_site`` through the same shared sequence Router Fleet's
   "Add Instant On site" uses (``onboard_instant_on_site``), and the site id
   written to ``instant_on_sites`` with polling and the customer view off;
2. no router-shaped side effect: no MikroTik ``create_router``, no config
   template, no WireGuard/hub call;
3. refusals before the first write: router + instant_on_site together, a
   template with no router, an already-mapped site id, a malformed site id,
   and an unwired Instant On service;
4. the mixed-vendor rule (``location_has_network_integration`` /
   ``location_has_other_devices``) still runs, inside the transaction, and
   its refusal rolls the whole customer back;
5. any later failure rolls back the Aruba row with everything else -- it is
   a flush on the same unit of work;
6. the route stays GLOBAL-pinned, and its response names the vendor so the
   wizard can open the Instant On setup panel.

The provisioning fakes and transaction double are
``test_location_provisioning``'s; the router side is ``test_router``'s real
``RouterService`` over its in-memory repository, sharing the location dict
the real ``LocationService`` writes into.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.location.exceptions import (
    InstantOnProvisioningUnavailableError,
    ProvisioningDeviceConflictError,
    RouterConfigTemplateWithoutRouterError,
)
from app.domains.location.provisioning_schemas import (
    ProvisionLocationRequest,
    ProvisionLocationResponse,
)
from app.domains.location.provisioning_service import InstantOnSiteInput
from app.domains.location.router import (
    preview_provision_location as preview_provision_location_route,
)
from app.domains.location.router import (
    provision_location as provision_location_route,
)
from app.domains.network_integration.exceptions import (
    InstantOnSiteNotConfigurableError,
)
from app.domains.notification.onboarding_slack import OnboardingSlackNotifier
from app.domains.rbac.enums import ScopeType
from app.domains.router.exceptions import NasOnlySiteRefusedError
from app.domains.router.service import NAS_ONLY_SITE_MODEL, RouterService
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR

from .test_aruba_instant_on_site import _instant_on, _SiteRepo
from .test_location_provisioning import (
    _DEFAULT_ROUTER,
    _fake_request,
    _input,
    _new_org,
    _request_payload,
    _router_shaped,
    _UnusedEnqueuer,
    make_service,
    run_within_transaction,
)
from .test_router import FakeLocationLookup, FakeRouterRepository
from .test_router import make_service as make_router_service

_SITE_ID = "fe0177b6-2ff9-4c0b-9326-091953c67f5f"
_AP_SERIAL = "VNV5M1K1M6"
_AP_MAC = "54:F0:B1:C8:A9:0A"


class _SessionBoundRouterRepository(FakeRouterRepository):
    """``test_router``'s repository, recording its writes on the provisioning
    test's shared session -- the way the real repository flushes on the one
    request-scoped ``AsyncSession`` -- so rollback is observable."""

    def __init__(self, session: Any) -> None:
        super().__init__()
        self._session = session

    async def create_router(self, **fields: object):  # noqa: ANN201
        router = await super().create_router(**fields)
        self._session.flush(f"router.create_nas_only:{fields.get('vendor')}")
        return router


def _wire(*, wired: bool = True, fail_at: str | None = None):  # noqa: ANN202
    """The provisioning service with a REAL ``RouterService`` (NAS-only row
    creation) and a REAL ``InstantOnReadService`` (site mapping)."""
    service, fakes, plan_id = make_service(fail_at=fail_at)
    location_repository = service.location_service.repository
    _router_service, _repo, _locations, org_lookup, audit = make_router_service()
    repo = _SessionBoundRouterRepository(fakes.session)
    router_service = RouterService(
        repo,
        # Shares the dict the real LocationService writes the new location
        # into, so `create_nas_only_site` finds it exactly as the request
        # session would.
        FakeLocationLookup(
            organization_lookup=org_lookup,
            locations=location_repository.locations,
        ),
        org_lookup,
        audit_writer=audit,
        provisioning_token_ttl_hours=24,
    )
    # The MikroTik path's `create_router` stays the spy fake; only the
    # NAS-only methods are the real ones. Any MikroTik call would still show
    # up as "router.create" in `fakes.calls`.
    service.router_service = _SplitRouterService(fakes, router_service)
    sites = _SiteRepo(repo.routers)
    if wired:
        service.instant_on_service = _instant_on(sites, audit)
    else:
        service.instant_on_service = None
    return service, fakes, plan_id, repo, sites, audit


class _SplitRouterService:
    """MikroTik ``create_router`` -> the spy fake; NAS-only creation and
    ``get_router`` -> the real ``RouterService``."""

    def __init__(self, fakes: Any, real: RouterService) -> None:
        self._fakes = fakes
        self.real = real

    async def create_router(self, **kwargs: object):  # noqa: ANN201
        return await self._fakes.create_router(**kwargs)

    async def create_nas_only_site(self, **kwargs: object):  # noqa: ANN201
        self._fakes.calls.append("instant_on.create_nas_only_site")
        return await self.real.create_nas_only_site(**kwargs)

    async def get_router(self, router_id, **kwargs):  # noqa: ANN001, ANN003, ANN201
        return await self.real.get_router(router_id, **kwargs)


def _aruba(**overrides: object) -> InstantOnSiteInput:
    base: dict[str, Any] = {
        "name": "Aruba AP21 Lobby",
        "serial_number": _AP_SERIAL,
        "mac_address": _AP_MAC,
        "instant_on_site_id": _SITE_ID,
        "instant_on_site_name": "inhouse-office",
    }
    base.update(overrides)
    return InstantOnSiteInput(**base)


def _aruba_input(plan_id: uuid.UUID, **site: object):  # noqa: ANN202
    return dataclasses.replace(
        _input(new_organization=_new_org(), plan_id=plan_id, router=None),
        instant_on_site=_aruba(**site),
    )


# ---------------------------------------------------------------------------
# 1-2. One Aruba row, the site mapping, nothing router-shaped
# ---------------------------------------------------------------------------


class TestCreatesExactlyOneArubaRow:
    async def test_one_nas_only_row_and_nothing_router_shaped(self) -> None:
        service, fakes, plan_id, repo, sites, _audit = _wire()

        result = await run_within_transaction(
            fakes.session,
            service.provision_location(
                actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
            ),
        )

        [row] = repo.routers.values()
        assert row.vendor == ARUBA_INSTANT_ON_VENDOR
        assert row.model == NAS_ONLY_SITE_MODEL
        assert row.serial_number == _AP_SERIAL
        assert row.mac_address == _AP_MAC
        assert row.location_id == result.location_id
        assert row.organization_id == result.organization_id
        # No agent-shaped field is set on a NAS-only row.
        assert row.snmp_enabled is False
        assert row.api_credentials_encrypted is None
        assert row.management_ip_address is None

        # Nothing MikroTik-shaped: no create_router, no template, no hub.
        assert "router.create" not in fakes.calls
        assert _router_shaped(fakes.calls) == []
        assert "router_provisioning.list_templates" not in fakes.calls
        assert fakes.calls.count("instant_on.create_nas_only_site") == 1
        assert result.tunnel_ip_address is None

        # The result names the Aruba row, so the wizard can open its panel.
        assert result.router_id == row.id
        assert result.router_name == "Aruba AP21 Lobby"
        assert result.router_vendor == ARUBA_INSTANT_ON_VENDOR
        assert result.instant_on_site_id == _SITE_ID
        assert fakes.session.committed is True

    async def test_site_mapping_is_written_with_both_flags_off(self) -> None:
        service, fakes, plan_id, repo, sites, audit = _wire()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
        )

        [site] = sites.sites
        [row] = repo.routers.values()
        assert site.router_id == row.id
        assert site.site_id == _SITE_ID
        assert site.site_name == "inhouse-office"
        assert site.poll_enabled is False
        assert site.customer_visible is False
        assert site.organization_id == result.organization_id
        assert site.location_id == result.location_id
        assert "instant_on_site.create" in [e["action"] for e in audit.entries]

    async def test_without_a_site_id_identity_is_minted_and_no_mapping(self) -> None:
        service, _fakes, plan_id, repo, sites, _audit = _wire()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_aruba_input(
                plan_id,
                serial_number=None,
                mac_address=None,
                instant_on_site_id=None,
                instant_on_site_name=None,
            ),
        )

        [row] = repo.routers.values()
        assert row.serial_number.startswith("AIO-")
        assert row.settings["synthetic_identity"] is True
        assert sites.sites == []
        assert result.instant_on_site_id is None

    async def test_audit_names_the_aruba_row(self) -> None:
        service, fakes, plan_id, repo, _sites, _audit = _wire()

        await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
        )

        [row] = repo.routers.values()
        [provisioned] = [
            e for e in fakes.audit_entries if e["action"] == "location_provisioned"
        ]
        assert provisioned["event_metadata"]["router_id"] == str(row.id)  # type: ignore[index]

    async def test_owner_and_temporary_password_are_unchanged(self) -> None:
        service, fakes, plan_id, _repo, _sites, _audit = _wire()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
        )

        assert result.owner_temporary_password
        assert "user.create" in fakes.calls
        assert "identity.update_user" in fakes.calls
        assert "email.send" in fakes.calls

    async def test_mikrotik_path_still_reports_its_vendor_and_no_aruba_row(
        self,
    ) -> None:
        service, fakes, plan_id, repo, sites, _audit = _wire()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=plan_id),
        )

        assert repo.routers == {}
        assert sites.sites == []
        assert "router.create" in fakes.calls
        assert "instant_on.create_nas_only_site" not in fakes.calls
        assert result.tunnel_ip_address == "10.100.0.5"
        assert result.instant_on_site_id is None


# ---------------------------------------------------------------------------
# 3. Refusals before the first write
# ---------------------------------------------------------------------------


class TestRefusedBeforeAnyWrite:
    async def test_router_and_instant_on_site_together(self) -> None:
        service, fakes, plan_id, repo, _sites, _audit = _wire()
        data = dataclasses.replace(
            _input(new_organization=_new_org(), plan_id=plan_id),
            instant_on_site=_aruba(),
        )

        with pytest.raises(ProvisioningDeviceConflictError) as excinfo:
            await service.provision_location(actor_user_id=uuid.uuid4(), data=data)

        assert excinfo.value.status_code == 422
        assert fakes.session.flushed == []
        assert repo.routers == {}

    async def test_template_with_an_instant_on_site_is_refused(self) -> None:
        service, fakes, plan_id, _repo, _sites, _audit = _wire()
        data = dataclasses.replace(
            _aruba_input(plan_id), router_config_template_id=uuid.uuid4()
        )

        with pytest.raises(RouterConfigTemplateWithoutRouterError):
            await service.provision_location(actor_user_id=uuid.uuid4(), data=data)

        assert fakes.session.flushed == []

    async def test_site_already_mapped_to_a_live_row(self) -> None:
        service, fakes, plan_id, repo, sites, _audit = _wire()
        await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
        )
        [first] = repo.routers.values()
        fakes.session.flushed.clear()
        fakes.calls.clear()

        with pytest.raises(NasOnlySiteRefusedError) as excinfo:
            await service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_aruba_input(plan_id, serial_number=None, mac_address=None),
            )

        assert excinfo.value.reason == "site_already_onboarded"
        assert excinfo.value.data["existing_router_id"] == str(first.id)
        assert excinfo.value.status_code == 409
        # Refused before the organization was even created.
        assert fakes.session.flushed == []
        assert fakes.calls == []
        assert len(repo.routers) == 1
        assert len(sites.sites) == 1

    async def test_malformed_site_id(self) -> None:
        service, fakes, plan_id, repo, _sites, _audit = _wire()

        with pytest.raises(InstantOnSiteNotConfigurableError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_aruba_input(plan_id, instant_on_site_id="../../etc"),
            )

        assert fakes.session.flushed == []
        assert repo.routers == {}

    async def test_unwired_instant_on_service(self) -> None:
        service, fakes, plan_id, repo, _sites, _audit = _wire(wired=False)

        with pytest.raises(InstantOnProvisioningUnavailableError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
            )

        assert fakes.session.flushed == []
        assert repo.routers == {}


# ---------------------------------------------------------------------------
# 4-5. The mixed-vendor rule and rollback
# ---------------------------------------------------------------------------


class TestRollback:
    async def test_mixed_vendor_refusal_rolls_back_the_whole_customer(
        self,
    ) -> None:
        """The location is brand new, so the only way the "no mixed venues"
        rule can bite here is something else at that location in the same
        transaction -- simulated as a live network integration. The refusal
        is the real ``create_nas_only_site`` one, and it rolls back the
        organization, location and owner already flushed."""
        service, fakes, plan_id, repo, sites, _audit = _wire()

        async def _one_integration(_location_id: uuid.UUID) -> int:
            return 1

        repo.count_live_integrations_at_location = _one_integration  # type: ignore[method-assign]

        with pytest.raises(NasOnlySiteRefusedError) as excinfo:
            await run_within_transaction(
                fakes.session,
                service.provision_location(
                    actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
                ),
            )

        assert excinfo.value.reason == "location_has_network_integration"
        assert "organization.create" in fakes.session.flushed
        assert fakes.session.rolled_back is True
        assert fakes.session.committed is False
        assert repo.routers == {}
        assert sites.sites == []

    async def test_a_failure_after_the_row_rolls_the_row_back_too(self) -> None:
        service, fakes, plan_id, _repo, _sites, _audit = _wire(
            fail_at="captive_portal.create_config"
        )

        with pytest.raises(RuntimeError, match="captive_portal.create_config"):
            await run_within_transaction(
                fakes.session,
                service.provision_location(
                    actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
                ),
            )

        # The Aruba row was a flush on the same unit of work...
        assert (
            f"router.create_nas_only:{ARUBA_INSTANT_ON_VENDOR}" in fakes.session.flushed
        )
        # ...which was rolled back, not committed.
        assert fakes.session.rolled_back is True
        assert fakes.session.committed is False
        assert _router_shaped(fakes.calls) == []


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------


class TestPreview:
    async def test_preview_names_the_site_and_writes_nothing(self) -> None:
        service, fakes, plan_id, repo, _sites, _audit = _wire()
        fakes.system_templates.clear()

        preview = await service.preview_provision_location(data=_aruba_input(plan_id))

        assert preview.router_name == "Aruba AP21 Lobby"
        assert preview.controller_id == _AP_SERIAL
        assert fakes.session.flushed == []
        assert repo.routers == {}
        # No template lookup: an Instant On venue gets none.
        assert "router_provisioning.list_templates" not in fakes.calls

    async def test_preview_refuses_an_already_mapped_site(self) -> None:
        service, _fakes, plan_id, _repo, _sites, _audit = _wire()
        await service.provision_location(
            actor_user_id=uuid.uuid4(), data=_aruba_input(plan_id)
        )

        with pytest.raises(NasOnlySiteRefusedError):
            await service.preview_provision_location(
                data=_aruba_input(plan_id, serial_number=None, mac_address=None)
            )


# ---------------------------------------------------------------------------
# 6. Request schema, route, scope
# ---------------------------------------------------------------------------


_SITE_BODY = {
    "name": "Aruba AP21 Lobby",
    "serial_number": _AP_SERIAL,
    "mac_address": "54-f0-b1-c8-a9-0a",
    "instant_on_site_id": _SITE_ID,
    "instant_on_site_name": "inhouse-office",
}


class TestRequestSchema:
    def test_instant_on_site_is_accepted_and_normalized(self) -> None:
        request = ProvisionLocationRequest.model_validate(
            _request_payload(instant_on_site=_SITE_BODY)
        )
        assert request.router is None
        assert request.instant_on_site is not None
        assert request.instant_on_site.mac_address == _AP_MAC

    def test_router_and_instant_on_site_together_is_a_422(self) -> None:
        with pytest.raises(ValidationError, match="instant_on_site"):
            ProvisionLocationRequest.model_validate(
                _request_payload(
                    instant_on_site=_SITE_BODY,
                    router={
                        "name": "Lobby Router",
                        "serial_number": "SN-1",
                        "mac_address": "AA:BB:CC:DD:EE:01",
                        "model": "RB5009",
                    },
                )
            )

    def test_unknown_keys_are_refused_not_ignored(self) -> None:
        with pytest.raises(ValidationError):
            ProvisionLocationRequest.model_validate(
                _request_payload(instant_on_site={**_SITE_BODY, "site_id": "x"})
            )

    def test_site_name_without_site_id_is_refused(self) -> None:
        body = {"name": "AP", "instant_on_site_name": "office"}
        with pytest.raises(ValidationError, match="instant_on_site_id"):
            ProvisionLocationRequest.model_validate(
                _request_payload(instant_on_site=body)
            )

    def test_template_with_instant_on_site_is_a_422(self) -> None:
        with pytest.raises(ValidationError, match="router_config_template_id"):
            ProvisionLocationRequest.model_validate(
                _request_payload(
                    instant_on_site=_SITE_BODY,
                    router_config_template_id=str(uuid.uuid4()),
                )
            )


class TestRoute:
    async def test_route_returns_the_aruba_row_and_its_vendor(self) -> None:
        service, _fakes, plan_id, repo, sites, _audit = _wire()
        payload = ProvisionLocationRequest.model_validate(
            _request_payload(plan_id=str(plan_id), instant_on_site=_SITE_BODY)
        )

        response = await provision_location_route(
            request=_fake_request(),
            payload=payload,
            user=AuthUser(id=str(uuid.uuid4()), email="admin@wyfy.example.com"),
            provisioning_service=service,
            onboarding_slack=OnboardingSlackNotifier(
                notification_service=_UnusedEnqueuer(), enabled=False
            ),
            settings=get_settings(),
        )

        data = response["data"]
        [row] = repo.routers.values()
        assert set(data) == set(ProvisionLocationResponse.model_fields)
        assert data["router_id"] == str(row.id)
        assert data["router_vendor"] == ARUBA_INSTANT_ON_VENDOR
        assert data["instant_on_site_id"] == _SITE_ID
        assert data["tunnel_ip_address"] is None
        assert data["owner_temporary_password"]
        assert len(sites.sites) == 1

    async def test_preview_route_names_the_site(self) -> None:
        service, _fakes, plan_id, _repo, _sites, _audit = _wire()
        payload = ProvisionLocationRequest.model_validate(
            _request_payload(plan_id=str(plan_id), instant_on_site=_SITE_BODY)
        )

        response = await preview_provision_location_route(
            request=_fake_request(), payload=payload, provisioning_service=service
        )

        assert response["data"]["router_name"] == "Aruba AP21 Lobby"
        assert response["data"]["controller_id"] == _AP_SERIAL


def _pinned(path: str) -> dict:
    from app.domains.location.router import router as location_router

    route = next(
        r for r in location_router.routes if r.path == path and "POST" in r.methods
    )
    closures = [
        {
            type(cell.cell_contents): cell.cell_contents
            for cell in (getattr(d.dependency, "__closure__", None) or ())
        }
        for d in route.dependencies
    ]
    pinned = [c for c in closures if ScopeType in c]
    assert pinned, closures
    return pinned[0]


class TestScope:
    @pytest.mark.parametrize(
        "path", ["/locations/provision", "/locations/provision/preview"]
    )
    def test_provision_routes_are_pinned_global(self, path: str) -> None:
        dep = _pinned(path)
        assert dep[ScopeType] == ScopeType.GLOBAL
        assert dep[str] == "locations.manage"


class TestOneSharedSequence:
    def test_both_entry_points_use_onboard_instant_on_site(self) -> None:
        """Router Fleet's "Add Instant On site" and this wizard run the same
        sequence; a copy in either would be free to drift."""
        from app.domains.location import provisioning_service
        from app.domains.router import router as router_routes
        from app.domains.router.instant_on_onboarding import onboard_instant_on_site

        assert router_routes.onboard_instant_on_site is onboard_instant_on_site
        assert provisioning_service.onboard_instant_on_site is onboard_instant_on_site
        assert "onboard_instant_on_site" in (
            router_routes.create_instant_on_site.__code__.co_names
        )

    def test_mikrotik_default_router_is_unchanged(self) -> None:
        # Guard: the shared fixture this module builds on is still MikroTik.
        assert _DEFAULT_ROUTER.model == "RB5009"

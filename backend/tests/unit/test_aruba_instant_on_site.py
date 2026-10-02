"""Adding (and removing) an Aruba Instant On site from the Master console.

``POST /platform/routers/instant-on-sites`` creates one ``aruba_instant_on``
fleet row per Instant On site (PM_SPEC §0.1 items 1, 3-5). What is pinned:

1. the route is GLOBAL-pinned (``routers.create``), and so is the
   ``DELETE /routers/{id}`` it is removed with;
2. cross-tenant: a location that is not the named organization's own is
   refused, including an MSP child's location, before anything is written;
3. one row per site: a second Instant On row at the location, or a second
   live row with the same Instant On site id, is refused with the existing
   row's id;
4. no mixed venues: a location with any other live device, or with a live
   network integration, is refused;
5. no side effects: the row is the only write -- no agent credential,
   provisioning token, WireGuard peer, RouterOS call or RADIUS NAS -- and its
   vendor/model/status are what the NAS-only gates expect;
6. identity: serial/MAC optional (minted, visibly synthetic, locally
   administered MAC), real ones normalized, duplicates refused, and a
   decommissioned Instant On row's identity released so remove-then-re-add
   works;
7. the org-scoped ``POST /locations/{id}/routers`` refuses the NAS-only
   vendor (all Instant On onboarding is Master-only);
8. removal reuses decommission, which deregisters the RADIUS client first and
   aborts with nothing changed if the hub refuses.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.common.exceptions import register_exception_handlers
from app.domains.auth.models import AuthUser
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.organization.enums import OrganizationType
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    get_access_validator,
    get_current_user,
)
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.router.dependencies import get_router_service
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import (
    DuplicateMacAddressError,
    DuplicateSerialNumberError,
    NasOnlySiteRefusedError,
)
from app.domains.router.schemas import NasOnlySiteCreateRequest
from app.domains.router.service import (
    NAS_ONLY_SITE_MODEL,
    NAS_ONLY_SYNTHETIC_SERIAL_PREFIX,
    synthesize_nas_only_identity,
)
from app.domains.router.vendor_capabilities import (
    ARUBA_INSTANT_ON_VENDOR,
    MIKROTIK_MODEL_MARKERS,
    is_agent_managed,
    is_nas_only,
    looks_like_mikrotik_hardware,
)

from .test_router import make_router, make_service

_ACTOR_ID = uuid.uuid4()
_ACTOR = AuthUser(id=str(_ACTOR_ID), email="ops@wyfy.example")
_AP21_SERIAL = "VNV5M1K1M6"
_AP21_MAC = "54:F0:B1:C8:A9:0A"
_SITE_ID = "fe0177b6-2ff9-4c0b-9326-091953c67f5f"


def _setup():  # noqa: ANN202
    service, repo, locations, orgs, audit = make_service()
    org = orgs.add()
    location = locations.add(organization_id=org.id)
    return service, repo, locations, orgs, audit, org, location


async def _create(service, org, location, **overrides):  # noqa: ANN001, ANN003, ANN202
    kwargs: dict[str, Any] = {
        "actor_user_id": _ACTOR_ID,
        "organization_id": org.id,
        "location_id": location.id,
        "name": "Aruba AP21 VNV5M1K1M6",
    }
    kwargs.update(overrides)
    return await service.create_nas_only_site(**kwargs)


# ---------------------------------------------------------------------------
# 1. Scope pinning
# ---------------------------------------------------------------------------


def _pinned(path: str, method: str) -> dict:
    from app.domains.router.router import router as router_router

    route = next(
        r for r in router_router.routes if r.path == path and method in r.methods
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


class TestRoutesArePinnedToGlobalScope:
    """Introspect the mounted routes, so deleting `scope=` fails here."""

    def test_create_site_is_global_routers_create(self) -> None:
        dep = _pinned("/platform/routers/instant-on-sites", "POST")
        assert dep[ScopeType] == ScopeType.GLOBAL
        # An existing action: no new RBAC key, so no manual re-seed.
        assert dep[str] == "routers.create"

    def test_remove_is_global_routers_delete(self) -> None:
        dep = _pinned("/routers/{router_id}", "DELETE")
        assert dep[ScopeType] == ScopeType.GLOBAL
        assert dep[str] == "routers.delete"

    def test_create_site_route_takes_no_header_organization(self) -> None:
        """The tenant is in the body and checked against the location; the
        route must not also resolve `X-Organization-Id` and act on it."""
        from app.domains.router.router import create_instant_on_site

        assert "requesting_organization_id" not in (
            create_instant_on_site.__code__.co_varnames
        )


# ---------------------------------------------------------------------------
# 2. Cross-tenant
# ---------------------------------------------------------------------------


class TestCrossTenant:
    async def test_location_of_another_organization_is_refused(self) -> None:
        service, repo, locations, orgs, _audit, org, _location = _setup()
        other_org = orgs.add()
        other_location = locations.add(organization_id=other_org.id)

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(service, org, other_location)

        assert exc.value.status_code == 422
        assert exc.value.data["reason"] == "location_not_in_organization"
        assert repo.routers == {}

    async def test_msp_parent_naming_a_child_location_is_refused(self) -> None:
        """`get_location(requesting_organization_id=parent)` would accept a
        child's location. The row would land under the CHILD while the
        operator named the parent -- refused, the ids must match exactly."""
        service, repo, locations, orgs, _audit, _org, _location = _setup()
        parent = orgs.add(org_type=OrganizationType.MSP.value)
        child = orgs.add(parent_organization_id=parent.id)
        child_location = locations.add(organization_id=child.id)

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(service, parent, child_location)

        assert exc.value.data["reason"] == "location_not_in_organization"
        assert repo.routers == {}

    async def test_unknown_location_is_not_found(self) -> None:
        service, repo, _locations, _orgs, _audit, org, _location = _setup()

        class _Missing:
            id = uuid.uuid4()

        with pytest.raises(LocationNotFoundError):
            await _create(service, org, _Missing())
        assert repo.routers == {}

    async def test_row_takes_the_locations_organization(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        router, _s, _m = await _create(service, org, location)
        assert router.organization_id == org.id == location.organization_id
        assert router.location_id == location.id


# ---------------------------------------------------------------------------
# 3. One row per site
# ---------------------------------------------------------------------------


class TestOneRowPerSite:
    async def test_second_site_at_the_same_location_is_refused(self) -> None:
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        first, _s, _m = await _create(service, org, location)

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(service, org, location, name="Second")

        assert exc.value.status_code == 409
        assert exc.value.data["reason"] == "already_onboarded"
        assert exc.value.data["existing_router_id"] == str(first.id)
        assert exc.value.data["code"] == "NAS_ONLY_SITE_REFUSED"
        assert len(repo.routers) == 1

    async def test_same_instant_on_site_id_at_another_location_is_refused(
        self,
    ) -> None:
        service, repo, locations, _orgs, _audit, org, location = _setup()
        first, _s, _m = await _create(
            service, org, location, instant_on_site_id=_SITE_ID
        )
        second_location = locations.add(organization_id=org.id)

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(
                service, org, second_location, instant_on_site_id=_SITE_ID
            )

        assert exc.value.data["reason"] == "site_already_onboarded"
        assert exc.value.data["existing_router_id"] == str(first.id)
        assert len(repo.routers) == 1

    async def test_a_removed_site_can_be_added_again(self) -> None:
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        first, _s, _m = await _create(
            service, org, location, instant_on_site_id=_SITE_ID
        )
        await service.decommission_router(
            actor_user_id=_ACTOR_ID,
            router_id=first.id,
            requesting_organization_id=None,
        )

        second, _s, _m = await _create(
            service, org, location, instant_on_site_id=_SITE_ID
        )
        assert second.id != first.id
        assert not second.is_deleted


# ---------------------------------------------------------------------------
# 4. Mixed-vendor locations
# ---------------------------------------------------------------------------


class TestNoMixedVenues:
    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_location_with_another_device_is_refused(self, vendor: str) -> None:
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        other = await make_router(
            repo, location_id=location.id, organization_id=org.id
        )
        other.vendor = vendor

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(service, org, location)

        assert exc.value.status_code == 409
        assert exc.value.data["reason"] == "location_has_other_devices"
        assert exc.value.data["existing_router_id"] == str(other.id)
        assert len(repo.routers) == 1

    async def test_suspended_device_still_counts(self) -> None:
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        await make_router(
            repo,
            location_id=location.id,
            organization_id=org.id,
            status=RouterStatus.SUSPENDED,
        )
        with pytest.raises(NasOnlySiteRefusedError):
            await _create(service, org, location)

    async def test_decommissioned_device_does_not_count(self) -> None:
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        old = await make_router(
            repo, location_id=location.id, organization_id=org.id
        )
        await service.decommission_router(
            actor_user_id=_ACTOR_ID, router_id=old.id, requesting_organization_id=None
        )
        router, _s, _m = await _create(service, org, location)
        assert router.vendor == ARUBA_INSTANT_ON_VENDOR

    async def test_location_with_a_network_integration_is_refused(self) -> None:
        """An Omada integration that has no fleet row yet still serves the
        location."""
        service, repo, _locations, _orgs, _audit, org, location = _setup()
        repo.location_integration_counts[location.id] = 1

        with pytest.raises(NasOnlySiteRefusedError) as exc:
            await _create(service, org, location)

        assert exc.value.data["reason"] == "location_has_network_integration"
        assert repo.routers == {}

    async def test_other_locations_devices_do_not_matter(self) -> None:
        service, repo, locations, _orgs, _audit, org, location = _setup()
        elsewhere = locations.add(organization_id=org.id)
        await make_router(repo, location_id=elsewhere.id, organization_id=org.id)
        router, _s, _m = await _create(service, org, location)
        assert router.location_id == location.id


# ---------------------------------------------------------------------------
# 5. No side effects; the row is what the NAS-only gates expect
# ---------------------------------------------------------------------------


class TestNoSideEffects:
    async def test_only_the_row_and_its_audit_entry_are_written(self) -> None:
        service, repo, _locations, _orgs, audit, org, location = _setup()
        router, _s, _m = await _create(service, org, location)

        assert list(repo.routers) == [router.id]
        assert repo.tokens == {}
        assert router.api_username is None
        assert router.api_credentials_encrypted is None
        assert router.snmp_enabled is False
        assert router.management_ip_address is None
        assert router.public_ip_address is None
        assert router.status == RouterStatus.PENDING_PROVISIONING.value
        assert [e["action"] for e in audit.entries] == [
            AuditAction.ROUTER_CREATED.value
        ]

    async def test_row_is_nas_only_and_never_agent_managed(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        router, _s, _m = await _create(service, org, location)
        assert router.vendor == ARUBA_INSTANT_ON_VENDOR
        assert is_nas_only(router)
        assert not is_agent_managed(router)
        assert router.model == NAS_ONLY_SITE_MODEL
        assert not looks_like_mikrotik_hardware(router.model)

    def test_the_model_string_trips_no_mikrotik_marker(self) -> None:
        folded = NAS_ONLY_SITE_MODEL.lower()
        assert not [m for m in MIKROTIK_MODEL_MARKERS if m in folded]

    async def test_route_calls_no_agent_wireguard_or_radius_dependency(
        self,
    ) -> None:
        from app.domains.router.router import router as router_router

        route = next(
            r
            for r in router_router.routes
            if r.path == "/platform/routers/instant-on-sites"
        )
        names = {
            getattr(d.call, "__name__", "")
            for d in route.dependant.dependencies
        }
        assert "get_router_service" in names
        for forbidden in (
            "get_wireguard_service",
            "get_radius_service",
            "get_router_agent_service",
            "get_router_provisioning_service",
        ):
            assert forbidden not in names

    async def test_site_details_are_recorded_on_the_row(self) -> None:
        service, _repo, _locations, _orgs, audit, org, location = _setup()
        router, _s, _m = await _create(
            service,
            org,
            location,
            instant_on_site_id=_SITE_ID,
            instant_on_site_name="inhouse-office",
        )
        assert router.settings["instant_on_site_id"] == _SITE_ID
        assert router.settings["instant_on_site_name"] == "inhouse-office"
        assert audit.entries[0]["event_metadata"]["instant_on_site_id"] == _SITE_ID


# ---------------------------------------------------------------------------
# 6. Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    async def test_minted_when_absent(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        router, synthetic_serial, synthetic_mac = await _create(service, org, location)

        assert synthetic_serial and synthetic_mac
        assert router.serial_number.startswith(NAS_ONLY_SYNTHETIC_SERIAL_PREFIX)
        first_octet = int(router.mac_address.split(":")[0], 16)
        assert first_octet & 0b10, "locally administered bit must be set"
        assert not first_octet & 0b1, "multicast bit must be clear"
        assert router.settings["synthetic_identity"] is True

    async def test_real_values_are_kept(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        router, synthetic_serial, synthetic_mac = await _create(
            service,
            org,
            location,
            serial_number=_AP21_SERIAL,
            mac_address=_AP21_MAC.lower(),
        )
        assert (synthetic_serial, synthetic_mac) == (False, False)
        assert router.serial_number == _AP21_SERIAL
        assert router.mac_address == _AP21_MAC
        assert router.settings["synthetic_identity"] is False

    def test_minting_is_deterministic_per_seed_and_distinct_across_seeds(
        self,
    ) -> None:
        seed = uuid.uuid4()
        assert synthesize_nas_only_identity(seed) == synthesize_nas_only_identity(seed)
        assert synthesize_nas_only_identity(seed) != synthesize_nas_only_identity(
            uuid.uuid4()
        )

    async def test_a_live_rows_serial_is_a_conflict(self) -> None:
        service, repo, locations, _orgs, _audit, org, _location = _setup()
        elsewhere = locations.add(organization_id=org.id)
        await make_router(
            repo,
            location_id=elsewhere.id,
            organization_id=org.id,
            serial_number=_AP21_SERIAL,
        )
        fresh = locations.add(organization_id=org.id)
        with pytest.raises(DuplicateSerialNumberError):
            await _create(service, org, fresh, serial_number=_AP21_SERIAL)

    async def test_a_live_rows_mac_is_a_conflict(self) -> None:
        service, repo, locations, _orgs, _audit, org, _location = _setup()
        elsewhere = locations.add(organization_id=org.id)
        await make_router(
            repo,
            location_id=elsewhere.id,
            organization_id=org.id,
            mac_address=_AP21_MAC,
        )
        fresh = locations.add(organization_id=org.id)
        with pytest.raises(DuplicateMacAddressError):
            await _create(service, org, fresh, mac_address=_AP21_MAC)

    async def test_remove_then_re_add_with_the_real_serial(self) -> None:
        """Added at the wrong location, removed, added at the right one: the
        unique index still holds the tombstone's serial/MAC, so without the
        release this is an IntegrityError (500) in production."""
        service, repo, locations, _orgs, audit, org, wrong = _setup()
        first, _s, _m = await _create(
            service, org, wrong, serial_number=_AP21_SERIAL, mac_address=_AP21_MAC
        )
        await service.decommission_router(
            actor_user_id=_ACTOR_ID, router_id=first.id, requesting_organization_id=None
        )
        right = locations.add(organization_id=org.id)

        second, _s, _m = await _create(
            service, org, right, serial_number=_AP21_SERIAL, mac_address=_AP21_MAC
        )

        assert second.serial_number == _AP21_SERIAL
        assert second.mac_address == _AP21_MAC
        assert first.serial_number != _AP21_SERIAL
        assert first.mac_address != _AP21_MAC
        assert first.serial_number.startswith(NAS_ONLY_SYNTHETIC_SERIAL_PREFIX)
        release = [
            e for e in audit.entries if e["action"] == AuditAction.ROUTER_UPDATED.value
        ]
        assert release and release[0]["entity_id"] == first.id
        assert release[0]["event_metadata"]["released_serial_number"] == _AP21_SERIAL

    async def test_a_decommissioned_mikrotiks_identity_is_not_touched(self) -> None:
        service, repo, locations, _orgs, _audit, org, location = _setup()
        elsewhere = locations.add(organization_id=org.id)
        old = await make_router(
            repo,
            location_id=elsewhere.id,
            organization_id=org.id,
            serial_number=_AP21_SERIAL,
        )
        await service.decommission_router(
            actor_user_id=_ACTOR_ID, router_id=old.id, requesting_organization_id=None
        )
        with pytest.raises(DuplicateSerialNumberError):
            await _create(service, org, location, serial_number=_AP21_SERIAL)
        assert old.serial_number == _AP21_SERIAL
        assert len(repo.routers) == 1


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


class TestRequestSchema:
    def _body(self, **over: object) -> dict:
        body: dict[str, object] = {
            "organization_id": str(uuid.uuid4()),
            "location_id": str(uuid.uuid4()),
            "name": "Aruba AP21",
        }
        body.update(over)
        return body

    def test_unknown_keys_are_refused_not_ignored(self) -> None:
        with pytest.raises(ValidationError):
            NasOnlySiteCreateRequest(**self._body(site_id=_SITE_ID))

    @pytest.mark.parametrize(
        "spelling", ["54:f0:b1:c8:a9:0a", "54-F0-B1-C8-A9-0A", "54f0b1c8a90a"]
    )
    def test_mac_spellings_normalize(self, spelling: str) -> None:
        req = NasOnlySiteCreateRequest(**self._body(mac_address=spelling))
        assert req.mac_address == _AP21_MAC

    def test_bad_mac_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            NasOnlySiteCreateRequest(**self._body(mac_address="54:F0:B1:C8:A9"))

    def test_blank_name_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            NasOnlySiteCreateRequest(**self._body(name="   "))

    def test_vendor_is_not_a_field(self) -> None:
        with pytest.raises(ValidationError):
            NasOnlySiteCreateRequest(**self._body(vendor="mikrotik"))


# ---------------------------------------------------------------------------
# HTTP: envelope, status codes, and the org-scoped route's refusal
# ---------------------------------------------------------------------------


class _PermitAll:
    async def check(self, *args: Any, **kwargs: Any) -> None:
        return None


def _app(service) -> FastAPI:  # noqa: ANN001
    from app.domains.router.router import router as router_router

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(router_router, prefix="/api/v1")
    app.dependency_overrides[get_router_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: _ACTOR
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: None
    return app


async def _post(app: FastAPI, path: str, body: dict) -> tuple[int, dict]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(path, json=body)
    return response.status_code, json.loads(response.text)


class TestHttp:
    async def test_201_with_the_platform_view(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        status, body = await _post(
            _app(service),
            "/api/v1/platform/routers/instant-on-sites",
            {
                "organization_id": str(org.id),
                "location_id": str(location.id),
                "name": "Aruba AP21 VNV5M1K1M6",
                "serial_number": _AP21_SERIAL,
                "instant_on_site_name": "inhouse-office",
            },
        )
        assert status == 201, body
        data = body["data"]
        assert data["router"]["vendor"] == ARUBA_INSTANT_ON_VENDOR
        assert data["router"]["serial_number"] == _AP21_SERIAL
        assert data["router"]["location_id"] == str(location.id)
        assert data["synthetic_serial_number"] is False
        assert data["synthetic_mac_address"] is True
        assert data["instant_on_site_name"] == "inhouse-office"

    async def test_409_carries_the_reason_and_the_existing_row(self) -> None:
        service, _repo, _locations, _orgs, _audit, org, location = _setup()
        first, _s, _m = await _create(service, org, location)
        status, body = await _post(
            _app(service),
            "/api/v1/platform/routers/instant-on-sites",
            {
                "organization_id": str(org.id),
                "location_id": str(location.id),
                "name": "Again",
            },
        )
        assert status == 409
        assert body["success"] is False
        assert body["data"]["reason"] == "already_onboarded"
        assert body["data"]["existing_router_id"] == str(first.id)

    async def test_422_for_another_organizations_location(self) -> None:
        service, repo, locations, orgs, _audit, org, _location = _setup()
        other = locations.add(organization_id=orgs.add().id)
        status, body = await _post(
            _app(service),
            "/api/v1/platform/routers/instant-on-sites",
            {
                "organization_id": str(org.id),
                "location_id": str(other.id),
                "name": "X",
            },
        )
        assert status == 422
        assert body["data"]["reason"] == "location_not_in_organization"
        assert repo.routers == {}

    async def test_org_scoped_create_refuses_the_nas_only_vendor(self) -> None:
        service, repo, _locations, _orgs, _audit, _org, location = _setup()
        status, body = await _post(
            _app(service),
            f"/api/v1/locations/{location.id}/routers",
            {
                "name": "Sneaky",
                "serial_number": _AP21_SERIAL,
                "mac_address": _AP21_MAC,
                "model": "AP21",
                "vendor": ARUBA_INSTANT_ON_VENDOR,
            },
        )
        assert status == 422
        assert body["data"]["reason"] == "master_console_only"
        assert repo.routers == {}


# ---------------------------------------------------------------------------
# 8. Removal: decommission deregisters an Instant On row's NAS first
# ---------------------------------------------------------------------------


class TestRemoveDeregistersTheNasFirst:
    """`DELETE /routers/{id}` is vendor-agnostic and already covered for a
    MikroTik in `test_radius_nas_deregistration.py`; this pins it for an
    Instant On row, whose NAS is keyed on a public IP and has no WireGuard
    peer."""

    @staticmethod
    def _fakes() -> tuple[Any, Any, Any]:
        class _FakeRequest:
            class state:  # noqa: N801 -- mirrors Starlette's request.state
                request_id = "test-request"

        class _FakeRouterService:
            def __init__(self) -> None:
                self.decommissioned: list[uuid.UUID] = []

            async def decommission_router(self, **kwargs: Any) -> None:
                self.decommissioned.append(kwargs["router_id"])

        class _NoPeer:
            async def revoke_tunnel(self, **kwargs: Any) -> None:
                from app.domains.wireguard.exceptions import (
                    WireGuardPeerNotFoundError,
                )

                raise WireGuardPeerNotFoundError(kwargs["router_id"])

        return _FakeRequest(), _FakeRouterService(), _NoPeer()

    async def _aruba_with_nas(self):  # noqa: ANN202
        from .test_guest import make_fixture
        from .test_radius_nas_deregistration import _register_nas

        fx = make_fixture()
        fx.router.vendor = ARUBA_INSTANT_ON_VENDOR
        await _register_nas(fx)
        return fx

    async def test_hub_refusal_aborts_with_nothing_removed(self) -> None:
        from app.domains.guest.exceptions import RadiusNasBridgeDeregistrationError
        from app.domains.router.router import decommission_router

        from .test_radius_nas_deregistration import _AGENT_501, bridge

        fx = await self._aruba_with_nas()
        request, router_service, wireguard = self._fakes()
        with bridge(_AGENT_501), pytest.raises(RadiusNasBridgeDeregistrationError):
            await decommission_router(
                request,
                fx.router.id,
                user=_ACTOR,
                requesting_organization_id=None,
                router_service=router_service,
                radius_service=fx.radius_service,
                wireguard_service=wireguard,
            )
        assert router_service.decommissioned == []

    async def test_success_deregisters_then_decommissions(self) -> None:
        from app.domains.router.router import decommission_router

        from .test_radius_nas_deregistration import (
            _AGENT_OK_ONE_REMOVED,
            _NAS_IDENTIFIER,
            bridge,
        )

        fx = await self._aruba_with_nas()
        request, router_service, wireguard = self._fakes()
        with bridge(_AGENT_OK_ONE_REMOVED) as stub:
            await decommission_router(
                request,
                fx.router.id,
                user=_ACTOR,
                requesting_organization_id=None,
                router_service=router_service,
                radius_service=fx.radius_service,
                wireguard_service=wireguard,
            )
        assert stub.calls[0]["json"] == {"nas_identifier": _NAS_IDENTIFIER}
        assert router_service.decommissioned == [fx.router.id]

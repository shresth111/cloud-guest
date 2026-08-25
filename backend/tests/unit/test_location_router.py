"""Regression test for the location-router composition fix: creating a
location through the plain, real-customer-facing ``POST
/organizations/{organization_id}/locations`` endpoint must now also
provision a location-scoped ``CaptivePortalConfig`` row.

Before this fix, this endpoint (backing ``LocationWizard.tsx``'s ordinary
self-serve "add a venue" flow) never created one at all -- only the separate
"smart provisioning" ``/locations/provision`` endpoint's orchestration did.
A real customer who used the ordinary flow, then separately uploaded a
logo/background via the Branding page, ended up with real branding assets
and zero ``captive_portal_configs`` row: confirmed live, all 4 production
organizations with uploaded branding are in exactly this state, and
``GET /captive-portal/resolve`` returns "no active captive portal config is
configured" for every one of them -- their guest portal never renders
anything at all.

This test calls the router's ``create_location`` coroutine directly (this
project's dominant style is service/composition-level unit tests over full
FastAPI ``TestClient`` integration tests -- see ``test_location.py``'s own
module docstring), with a real ``LocationService`` built from the same fakes
``test_location.py`` uses, plus a fake ``CaptivePortalService`` double that
just records its calls -- there is no live Postgres in this environment, and
recording the call shape is what a real ``CaptivePortalService.create_config``
call would receive is exactly what this fix needs verified.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from app.domains.auth.models import AuthUser
from app.domains.location.number_generator import LocationCodeCounterRepositoryProtocol
from app.domains.location.router import create_location
from app.domains.location.schemas import LocationCreateRequest
from app.domains.location.service import LocationService

from .test_location import (
    FakeAuditLogWriter,
    FakeLocationCodeCounterRepository,
    FakeLocationRepository,
    FakeOrganizationLookup,
)


@dataclass
class FakeCaptivePortalService:
    """Records every ``create_config`` call instead of touching a real
    repository -- this test only needs to verify the router now calls it,
    with the right organization/location/defaults, not re-verify
    ``CaptivePortalService.create_config``'s own validation (already covered
    by ``test_captive_portal.py``)."""

    calls: list[dict[str, object]] = field(default_factory=list)

    async def create_config(self, **fields: object) -> SimpleNamespace:
        self.calls.append(fields)
        return SimpleNamespace(id=uuid.uuid4(), **fields)


def _fake_request() -> SimpleNamespace:
    # `_request_id` only ever does `getattr(request.state, "request_id", "")`.
    return SimpleNamespace(state=SimpleNamespace())


def _create_payload(**overrides: object) -> LocationCreateRequest:
    base: dict[str, object] = {
        "name": "Sunset Cafe",
        "slug": f"sunset-cafe-{uuid.uuid4()}",
        "address_line1": "123 Beach Rd",
        "city": "Goa",
        "state_province": "Goa",
        "postal_code": "403001",
        "country": "IN",
    }
    base.update(overrides)
    return LocationCreateRequest(**base)


@pytest.mark.asyncio
async def test_create_location_also_provisions_a_captive_portal_config() -> None:
    org_lookup = FakeOrganizationLookup()
    organization = org_lookup.add()

    location_service = LocationService(
        FakeLocationRepository(),
        org_lookup,
        location_code_counter=FakeLocationCodeCounterRepository(),
        audit_writer=FakeAuditLogWriter(),
    )
    captive_portal_service = FakeCaptivePortalService()
    user = AuthUser(id=str(uuid.uuid4()), email="owner@example.com")

    response = await create_location(
        request=_fake_request(),
        organization_id=organization.id,
        payload=_create_payload(),
        user=user,
        requesting_organization_id=organization.id,
        location_service=location_service,
        captive_portal_service=captive_portal_service,
    )

    assert response["success"] is True
    location_id = uuid.UUID(response["data"]["id"])

    # The whole point of the fix: exactly one config, for the real new
    # location, not an organization-wide default.
    assert len(captive_portal_service.calls) == 1
    call = captive_portal_service.calls[0]
    assert call["organization_id"] == organization.id
    assert call["location_id"] == location_id
    assert call["is_default"] is False
    assert call["is_active"] is True
    # A fresh location must never be left with zero working sign-in
    # methods -- otp_email needs no SMS/WhatsApp provider configured.
    assert call["otp_email_enabled"] is True
    assert call["otp_sms_enabled"] is False
    assert call["otp_whatsapp_enabled"] is False
    assert call["voucher_enabled"] is False
    assert call["username_password_enabled"] is False
    assert call["social_login_enabled"] is False
    # See the router's own comment: this must be None, not the endpoint's
    # `requesting_organization_id`, or an MSP parent creating a location
    # under a child org it owns would be spuriously rejected here even
    # though LocationService.create_location already allowed it.
    assert call["requesting_organization_id"] is None


@pytest.mark.asyncio
async def test_msp_parent_creating_child_org_location_still_provisions_config() -> None:
    """The exact scenario the `requesting_organization_id=None` choice
    protects: an MSP parent org creating a location under a child org it
    owns. `LocationService.create_location`'s own tenant-scope check
    already allows this (see test_location.py's MSP-child tests); this
    asserts the captive-portal call doesn't regress it."""
    org_lookup = FakeOrganizationLookup()
    parent = org_lookup.add(org_type="msp")
    child = org_lookup.add(parent_organization_id=parent.id)

    location_service = LocationService(
        FakeLocationRepository(),
        org_lookup,
        location_code_counter=FakeLocationCodeCounterRepository(),
        audit_writer=FakeAuditLogWriter(),
    )
    captive_portal_service = FakeCaptivePortalService()
    user = AuthUser(id=str(uuid.uuid4()), email="msp-admin@example.com")

    response = await create_location(
        request=_fake_request(),
        organization_id=child.id,
        payload=_create_payload(),
        user=user,
        # The MSP parent's own id -- different from `organization_id`
        # (the child), which is exactly the case a naive pass-through of
        # this value into `create_config` would break.
        requesting_organization_id=parent.id,
        location_service=location_service,
        captive_portal_service=captive_portal_service,
    )

    assert response["success"] is True
    assert len(captive_portal_service.calls) == 1
    assert captive_portal_service.calls[0]["organization_id"] == child.id

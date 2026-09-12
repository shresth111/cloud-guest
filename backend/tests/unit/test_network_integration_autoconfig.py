""" "Configure controller automatically" -- the whole stack, one socket short.

Every test here drives the real ``NetworkIntegrationService`` through the
real ``OmadaProvider`` and the real gateway ``OmadaControllerAdapter``; only
the controller is fake, behind ``httpx.MockTransport``. Its payloads are
shaped from the OpenAPI document Omada Software Controller 5.15.24.19 serves
about itself (``GET /v3/api-docs``, read from our EC2 controller 2026-09-12),
so the seam, the gateway's HTTP client, token handling and JSON bodies all
run for real.

**None of this has touched a real controller.** These tests prove what this
platform sends and how it reacts; they cannot prove the controller accepts
it. The manual hardware recipe is in ``OMADA_OPERATOR_RUNBOOK.md``.

The load-bearing ones, if any of them starts failing, stop:

* ``test_a_path_id_from_another_tenant_is_not_found`` -- the path-id defect
  class this codebase has shipped fourteen times, on an endpoint that writes
  to a customer's hardware.
* ``test_two_organizations_on_one_site_are_both_refused`` -- two tenants must
  never both manage one controller site.
* ``test_a_dry_run_writes_nothing_anywhere`` and
  ``test_a_foreign_portal_on_the_ssid_is_a_conflict_and_nothing_changes``.
* ``test_happy_path_...`` asserting the operator password reaches the
  encrypted column and nowhere else.
"""

from __future__ import annotations

import copy
import json
import logging
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter

from app.core.config import Settings
from app.domains.network_integration import router as router_module
from app.domains.network_integration.constants import (
    ControllerAuthMode,
    ErrorCode,
    IntegrationEventStatus,
    IntegrationEventType,
    NetworkIntegrationAuditAction,
)
from app.domains.network_integration.crypto import decrypt_credentials
from app.domains.network_integration.exceptions import (
    ControllerSetupPreconditionsError,
    ControllerSiteSharedError,
    GuestSsidInUseError,
    GuestSsidNotFoundError,
    NetworkIntegrationEncryptionKeyNotConfiguredError,
    NetworkIntegrationNotFoundError,
    NetworkIntegrationOrganizationRequiredError,
    PortalConflictError,
    ProviderPermissionDeniedError,
)
from app.domains.network_integration.providers import omada as omada_provider_module
from app.domains.network_integration.providers.omada import OmadaProvider
from app.domains.network_integration.schemas import ControllerConfigureRequest
from app.domains.network_integration.service import NetworkIntegrationService
from app.domains.network_integration.validators import build_external_portal_url
from tests.unit.test_network_integration import (
    FakeAuditWriter,
    FakeRepository,
    _integration,
    _resolves_public,
)

OMADAC_ID = "15ab5e4b7c2ca6cd134a3fded6e2ec59"
SITE_ID = "6aa3913c3ee1605f71ac35a1"
GUEST_SSID_ID = "6aa39c6f3ee1605f71ac3622"
STAFF_SSID_ID = "6aa39c6f3ee1605f71ac3699"
SITES = f"/openapi/v1/{OMADAC_ID}/sites"
SITE = f"{SITES}/{SITE_ID}"


# ============================================================================
# The fake controller
# ============================================================================


def _ok(result: Any = None, **extra: Any) -> httpx.Response:
    return httpx.Response(
        200, json={"errorCode": 0, "msg": "Success.", "result": result, **extra}
    )


def _grid(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "totalRows": len(rows),
        "currentPage": 1,
        "currentSize": len(rows),
        "data": rows,
    }


def venue_voucher_portal(portal_id: str, ssids: list[str]) -> dict[str, Any]:
    """A venue's own Hotspot portal (``PortalDetailResOpenApiVO``,
    ``authType`` 11) holding the guest SSID."""
    return {
        "id": portal_id,
        "name": "Front Desk Vouchers",
        "enable": True,
        "ssidList": ssids,
        "networkList": [],
        "authType": 11,
        "authTimeout": {"authTimeout": 6},
        "httpsRedirectEnable": False,
        "landingPage": 1,
        "hotspot": {"enabledTypes": [3]},
    }


class MockController:
    """Stateful 5.15-shaped controller: writes land in state, so a second run
    sees what the first one did."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Any]] = []
        self.ssids = [
            {"ssidId": GUEST_SSID_ID, "name": "WyfyGuest", "band": 3},
            {"ssidId": STAFF_SSID_ID, "name": "Staff", "band": 3},
        ]
        self.portals: dict[str, dict[str, Any]] = {}
        # PortalAccessControlOpenApiVO, with entries a venue already relies on.
        self.access_control: dict[str, Any] = {
            "preAuthAccessEnable": True,
            "preAuthAccessPolicies": [
                {"idInt": 1, "type": 2, "url": "pms.hotel.example"},
                {"idInt": 2, "type": 1, "ip": "10.20.0.0", "subnetMask": 16},
            ],
            "freeAuthClientEnable": False,
            "freeAuthClientPolicies": [],
        }
        self.operators: dict[str, dict[str, Any]] = {}
        self.refuse: dict[tuple[str, str], int] = {}
        self._next = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def writes(self) -> list[tuple[str, str, Any]]:
        return [
            r
            for r in self.requests
            if r[0] in {"POST", "PATCH", "PUT", "DELETE"}
            and r[1] != "/openapi/authorize/token"
            and not r[1].endswith("/api/v2/hotspot/login")
        ]

    def last_body(self, method: str, path: str) -> Any:
        for m, p, body in reversed(self.requests):
            if m == method and p == path:
                return body
        raise AssertionError(f"no {method} {path}")

    def _id(self) -> str:
        self._next += 1
        return f"6aa3a0{self._next:018x}"

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        method, path = request.method, request.url.path
        self.requests.append((method, path, body))
        if (method, path) in self.refuse:
            return httpx.Response(
                200,
                json={
                    "errorCode": self.refuse[(method, path)],
                    "msg": "Operation forbidden.",
                },
            )
        if path == "/openapi/authorize/token":
            return _ok(
                {
                    "accessToken": "AT-token",
                    "tokenType": "bearer",
                    "expiresIn": 7200,
                    "refreshToken": "RT-token",
                }
            )
        if path == f"/{OMADAC_ID}/api/v2/hotspot/login":
            known = {op["name"]: op["password"] for op in self.operators.values()}
            if (
                body
                and body.get("password")
                and known.get(body.get("name")) == body["password"]
            ):
                return httpx.Response(
                    200,
                    json={
                        "errorCode": 0,
                        "msg": "Hotspot log in successfully.",
                        "result": {"token": "csrf"},
                    },
                    headers=[("set-cookie", "TPOMADA_SESSIONID=s; Path=/")],
                )
            return httpx.Response(
                200, json={"errorCode": -30109, "msg": "Invalid operator."}
            )
        if path == SITES:
            return _ok(_grid([{"siteId": SITE_ID, "name": "wyfyguest", "type": 0}]))
        if path == f"{SITE}/wireless-network/wlans":
            return _ok([{"wlanId": "wlan-1", "name": "Default"}])
        if path == f"{SITE}/wireless-network/wlans/wlan-1/ssids":
            return _ok(_grid(self.ssids))
        if path == f"{SITE}/portals":
            return _ok(
                [
                    {
                        k: p.get(k)
                        for k in (
                            "id",
                            "name",
                            "enable",
                            "ssidList",
                            "networkList",
                            "authType",
                        )
                    }
                    for p in self.portals.values()
                ]
            )
        if path == f"{SITE}/portal" and method == "POST":
            portal_id = self._id()
            self.portals[portal_id] = {
                **copy.deepcopy(body),
                "id": portal_id,
                "authTimeout": {"authTimeout": 0, **body["authTimeout"]},
            }
            return httpx.Response(200, json={"errorCode": 0, "msg": "Success."})
        if path.startswith(f"{SITE}/portal/"):
            portal_id = path.rsplit("/", 1)[1]
            if method == "GET":
                return _ok(self.portals[portal_id])
            self.portals[portal_id] = {
                **copy.deepcopy(body),
                "id": portal_id,
                "authTimeout": {"authTimeout": 0, **body["authTimeout"]},
            }
            return httpx.Response(200, json={"errorCode": 0, "msg": "Success."})
        if path == f"{SITE}/setting/access-control":
            if method == "PATCH":
                self.access_control = copy.deepcopy(body)
            return _ok(self.access_control)
        if path == f"{SITE}/hotspot/operators":
            if method == "POST":
                operator_id = self._id()
                self.operators[operator_id] = {"id": operator_id, **body}
                return _ok({})
            return _ok(_grid(list(self.operators.values())))
        return httpx.Response(404)


async def _no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def controller(monkeypatch) -> MockController:
    """Install the mock controller under the REAL provider and adapter.

    Two seams are patched and nothing else: the gateway adapter gets a mock
    transport, and the provider's pre-call URL re-validation stops doing live
    DNS (the SSRF rules themselves are tested in test_network_integration.py).
    """
    mock = MockController()
    adapter = OmadaControllerAdapter(transport=mock.transport(), sleep=_no_sleep)
    monkeypatch.setitem(omada_provider_module._ADAPTER_CACHE, "adapter", adapter)

    async def _validated(url: str, **_: Any) -> SimpleNamespace:
        return SimpleNamespace(base_url=url)

    monkeypatch.setattr(omada_provider_module, "validate_controller_url", _validated)
    return mock


# ============================================================================
# Repository, service, rows
# ============================================================================


@dataclass
class ScopedRepository(FakeRepository):
    """``FakeRepository`` plus the two reads this feature added, and a record
    of which by-id read was used -- so the 404 test can prove the foreign row
    was never loaded rather than loaded and refused."""

    unscoped_reads: list[uuid.UUID] = field(default_factory=list)
    updates: list[dict[str, object]] = field(default_factory=list)

    async def get_integration_by_id(self, integration_id, *, include_deleted=False):
        self.unscoped_reads.append(integration_id)
        return await super().get_integration_by_id(
            integration_id, include_deleted=include_deleted
        )

    async def get_integration_for_organization(
        self, integration_id, *, organization_id
    ):
        row = self.integrations.get(integration_id)
        if row is None or row.is_deleted or row.organization_id != organization_id:
            return None
        return row

    async def list_live_integrations_on_controller_site(
        self, *, provider, base_url, external_site_id, exclude_id
    ):
        return [
            row
            for row in self.integrations.values()
            if not row.is_deleted
            and row.provider == provider
            and row.base_url == base_url
            and row.external_site_id == external_site_id
            and row.id != exclude_id
        ]

    async def update_integration(self, integration, data):
        self.updates.append(dict(data))
        return await super().update_integration(integration, data)


def _service(
    repo: ScopedRepository,
    audit: FakeAuditWriter | None = None,
    *,
    settings: Settings | None = None,
) -> NetworkIntegrationService:
    return NetworkIntegrationService(
        repo,
        audit_writer=audit or FakeAuditWriter(),
        provider_resolver=lambda _kind: OmadaProvider(),
        url_resolver=_resolves_public,
        redis=None,
        settings=settings,
    )


def _row(org: uuid.UUID, location: uuid.UUID | None = None, **overrides: Any):
    """An Open API integration with no operator login yet -- the row a venue
    has after connecting an Open API app and picking a site and SSID."""
    fields: dict[str, Any] = {
        "organization_id": org,
        "location_id": location or uuid.uuid4(),
        "router_id": uuid.uuid4(),
        "with_guest_operator": False,
        "controller_id": OMADAC_ID,
        "external_site_id": SITE_ID,
        "guest_ssid_id": None,
        "guest_ssid_name": "WyfyGuest",
    }
    fields.update(overrides)
    return _integration(**fields)


async def _configure(service, row, *, dry_run=False, take_over=False, org=None):
    return await service.configure_controller(
        row.id,
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=org or row.organization_id,
        dry_run=dry_run,
        take_over_ssid_portal=take_over,
    )


def _outcomes(outcome) -> dict[str, str]:
    return {step.step: step.outcome for step in outcome.steps}


# ============================================================================
# Happy path, idempotency, drift
# ============================================================================


async def test_happy_path_creates_everything_and_stores_the_operator_encrypted(
    controller, caplog
) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    audit = FakeAuditWriter()
    service = _service(repo, audit)

    with caplog.at_level(logging.DEBUG):
        outcome = await _configure(service, row)

    assert outcome.ok is True and outcome.changed is True
    assert _outcomes(outcome) == {
        "portal": "created",
        "pre_auth_access": "created",
        "hotspot_operator": "created",
    }

    # The portal carries exactly the URL the integration card shows, split
    # into the controller's scheme and URL fields.
    expected = build_external_portal_url(
        organization_id=row.organization_id,
        location_id=row.location_id,
        router_id=row.router_id,
        provider=row.provider,
    )
    sent = controller.last_body("POST", f"{SITE}/portal")
    assert sent["authType"] == 4
    assert sent["externalPortal"] == {
        "hostType": 2,
        "serverUrlScheme": expected.scheme,
        "serverUrl": expected.host_and_query,
    }
    assert sent["ssidList"] == [GUEST_SSID_ID]
    assert sent["name"] == f"Wyfy Guest - Lobby ({row.id.hex[:8]})"
    assert outcome.portal_id in controller.portals
    assert outcome.pre_auth_host == "auth.wyfyguest.com"

    # The SSID id resolved from the stored name is persisted.
    assert row.guest_ssid_id == GUEST_SSID_ID

    # The operator exists on the controller, and its login is in the
    # encrypted column -- next to the Open API app, which is kept.
    (operator,) = controller.operators.values()
    stored = decrypt_credentials(row.credentials_encrypted)
    assert stored == {
        "client_id": "cid",
        "client_secret": "shh",
        "username": operator["name"],
        "password": operator["password"],
    }
    assert operator["name"] == f"wyfy-{row.id.hex[:12]}"
    assert operator["selectedSites"] == [SITE_ID]
    password = operator["password"]
    assert len(password) >= 32

    # ...and nowhere else.
    assert password not in row.credentials_encrypted
    response = router_module._controller_configure_response(outcome).model_dump()
    assert password not in json.dumps(response)
    assert password not in caplog.text
    (event,) = [
        e
        for e in repo.events
        if e.event_type == IntegrationEventType.CONTROLLER_CONFIGURED
    ]
    assert event.status == IntegrationEventStatus.OK.value
    assert password not in json.dumps(event.context, default=str) + (
        event.message or ""
    )
    assert event.context["saved"] == ["guest_ssid_id", "hotspot_operator_login"]
    assert (
        audit.entries[-1]["action"]
        == NetworkIntegrationAuditAction.CONTROLLER_CONFIGURED.value
    )
    assert password not in json.dumps(audit.entries, default=str)


async def test_the_second_run_is_all_unchanged_and_writes_nothing(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    service = _service(repo)
    await _configure(service, row)
    writes_after_first = len(controller.writes())

    outcome = await _configure(service, row)

    assert set(_outcomes(outcome).values()) == {"unchanged"}
    assert outcome.ok is True and outcome.changed is False
    assert len(controller.writes()) == writes_after_first


async def test_a_drifted_portal_url_is_updated(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    service = _service(repo)
    await _configure(service, row)
    (portal_id,) = controller.portals
    controller.portals[portal_id]["externalPortal"]["serverUrl"] = (
        f"auth.wyfyguest.com/stale?routerId={row.router_id}"
    )

    outcome = await _configure(service, row)

    assert _outcomes(outcome)["portal"] == "updated"
    step = next(s for s in outcome.steps if s.step == "portal")
    assert "externalPortal.serverUrl" in step.details["drift"]
    assert controller.portals[portal_id]["externalPortal"]["serverUrl"] == (
        outcome.portal_url_host_and_query
    )
    assert len(controller.portals) == 1


async def test_pre_auth_merge_preserves_every_existing_entry(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    before = copy.deepcopy(controller.access_control["preAuthAccessPolicies"])

    await _configure(_service(repo), row)

    sent = controller.last_body("PATCH", f"{SITE}/setting/access-control")
    assert sent["preAuthAccessPolicies"][: len(before)] == before
    assert sent["preAuthAccessPolicies"][len(before) :] == [
        {"type": 2, "url": "auth.wyfyguest.com"}
    ]
    assert sent["freeAuthClientEnable"] is False


# ============================================================================
# Refusals, and the dry run
# ============================================================================


async def test_a_foreign_portal_on_the_ssid_is_a_conflict_and_nothing_changes(
    controller,
) -> None:
    controller.portals["p-venue"] = venue_voucher_portal("p-venue", [GUEST_SSID_ID])
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    ciphertext_before = row.credentials_encrypted

    with pytest.raises(PortalConflictError) as exc:
        await _configure(_service(repo), row)

    assert exc.value.status_code == 409
    assert exc.value.data["code"] == ErrorCode.PORTAL_CONFLICT.value
    assert exc.value.data["portal_name"] == "Front Desk Vouchers"
    assert exc.value.data["portal_id"] == "p-venue"
    assert controller.writes() == []
    assert row.credentials_encrypted == ciphertext_before
    (event,) = repo.events
    assert event.status == IntegrationEventStatus.ERROR.value
    assert event.error_code == ErrorCode.PORTAL_CONFLICT.value


async def test_take_over_only_unbinds_the_ssid_from_the_foreign_portal(
    controller,
) -> None:
    before = venue_voucher_portal("p-venue", [GUEST_SSID_ID, STAFF_SSID_ID])
    controller.portals["p-venue"] = copy.deepcopy(before)
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))

    outcome = await _configure(_service(repo), row, take_over=True)

    assert _outcomes(outcome)["ssid_takeover"] == "updated"
    assert _outcomes(outcome)["portal"] == "created"
    foreign_writes = [
        w for w in controller.writes() if w[1] == f"{SITE}/portal/p-venue"
    ]
    assert [w[0] for w in foreign_writes] == ["PATCH"]
    sent = foreign_writes[0][2]
    assert sent["ssidList"] == [STAFF_SSID_ID]
    for key in (
        "name",
        "enable",
        "networkList",
        "authType",
        "httpsRedirectEnable",
        "landingPage",
        "hotspot",
    ):
        assert sent[key] == before[key], key
    # The 1-day preset, re-spelt as the request schema spells it.
    assert sent["authTimeout"] == {"customTimeout": 1, "customTimeoutUnit": 3}


async def test_a_dry_run_writes_nothing_anywhere(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    audit = FakeAuditWriter()
    ciphertext_before = row.credentials_encrypted

    outcome = await _configure(_service(repo, audit), row, dry_run=True)

    assert outcome.dry_run is True
    assert _outcomes(outcome) == {
        "portal": "created",
        "pre_auth_access": "created",
        "hotspot_operator": "created",
    }
    assert controller.writes() == []
    assert [r for r in controller.requests if r[0] != "GET"] == [
        r for r in controller.requests if r[1] == "/openapi/authorize/token"
    ]
    assert repo.updates == []
    assert repo.events == []
    assert audit.entries == []
    assert row.credentials_encrypted == ciphertext_before
    assert row.guest_ssid_id is None


async def test_an_unknown_guest_ssid_is_refused_before_any_write(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4(), guest_ssid_name="NoSuchNetwork"))
    with pytest.raises(GuestSsidNotFoundError):
        await _configure(_service(repo), row)
    assert controller.writes() == []


async def test_a_permission_refusal_is_a_failed_step_not_a_500(controller) -> None:
    controller.refuse[("PATCH", f"{SITE}/setting/access-control")] = -1005
    controller.access_control["preAuthAccessPolicies"] = []
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))

    outcome = await _configure(_service(repo), row)

    assert outcome.ok is False
    step = next(s for s in outcome.steps if s.step == "pre_auth_access")
    assert step.outcome == "failed" and step.provider_code == -1005
    assert "Open API" in step.message
    (event,) = repo.events
    assert event.status == IntegrationEventStatus.ERROR.value


async def test_a_permission_refusal_while_planning_is_its_own_code(controller) -> None:
    controller.refuse[("GET", f"{SITE}/portals")] = -1005
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    with pytest.raises(ProviderPermissionDeniedError) as exc:
        await _configure(_service(repo), row)
    assert exc.value.code is ErrorCode.PERMISSION_DENIED
    assert controller.writes() == []


# ============================================================================
# Preconditions
# ============================================================================


async def test_legacy_auth_mode_is_a_precondition_error(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(
        _row(
            uuid.uuid4(),
            auth_mode=ControllerAuthMode.LEGACY.value,
            with_guest_operator=True,
        )
    )
    with pytest.raises(ControllerSetupPreconditionsError) as exc:
        await _configure(_service(repo), row)
    assert exc.value.status_code == 409
    assert exc.value.data["code"] == ErrorCode.AUTOCONFIG_PRECONDITIONS.value
    assert exc.value.data["missing"] == ["openapi_required"]
    assert "Open API" in exc.value.message
    assert controller.requests == []


async def test_every_missing_piece_is_named_at_once(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(
        _row(
            uuid.uuid4(),
            is_enabled=False,
            router_id=None,
            external_site_id=None,
            guest_ssid_name=None,
        )
    )
    row.location_id = None
    with pytest.raises(ControllerSetupPreconditionsError) as exc:
        await _configure(_service(repo), row, dry_run=True)
    assert exc.value.data["missing"] == [
        "integration_disabled",
        "location_not_mapped",
        "site_not_selected",
        "fleet_device_missing",
        "guest_ssid_missing",
    ]
    # Shared wording with portal readiness, where the fact is the same one.
    assert "not mapped to a location" in exc.value.message
    assert controller.requests == []
    assert repo.events == []  # a dry run records nothing, refusals included


async def test_no_storable_encryption_key_refuses_before_the_controller(
    controller,
) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    service = _service(repo, settings=Settings(environment="production"))
    with pytest.raises(NetworkIntegrationEncryptionKeyNotConfiguredError):
        await _configure(service, row)
    assert controller.requests == []


# ============================================================================
# Tenancy
# ============================================================================


async def test_a_path_id_from_another_tenant_is_not_found(controller) -> None:
    repo = ScopedRepository()
    victim = repo.add(_row(uuid.uuid4()))
    attacker_org = uuid.uuid4()

    with pytest.raises(NetworkIntegrationNotFoundError) as exc:
        await _configure(_service(repo), victim, org=attacker_org)

    assert exc.value.status_code == 404
    # Not read-then-refused: the unscoped by-id read was never made.
    assert repo.unscoped_reads == []
    assert controller.requests == []
    assert repo.events == [] and repo.updates == []


async def test_the_customer_path_refuses_a_null_organization(controller) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    with pytest.raises(NetworkIntegrationOrganizationRequiredError):
        await _service(repo).configure_controller(
            row.id, actor_user_id=None, requesting_organization_id=None, dry_run=True
        )
    assert controller.requests == []


async def test_two_organizations_on_one_site_are_both_refused(controller) -> None:
    repo = ScopedRepository()
    ours = repo.add(_row(uuid.uuid4()))
    theirs = repo.add(_row(uuid.uuid4(), guest_ssid_name="Staff"))

    for row in (ours, theirs):
        with pytest.raises(ControllerSiteSharedError) as exc:
            await _configure(_service(repo), row)
        assert exc.value.status_code == 409
        other = theirs if row is ours else ours
        assert str(other.organization_id) not in exc.value.message
        assert "Acme" not in exc.value.message
    assert controller.requests == []


async def test_a_different_controller_behind_the_same_address_is_not_shared(
    controller,
) -> None:
    """A cloud edge fronts every controller in a region at one base URL; the
    Omada ID is what tells two of them apart."""
    repo = ScopedRepository()
    ours = repo.add(_row(uuid.uuid4()))
    repo.add(_row(uuid.uuid4(), controller_id="ffffffffffffffffffffffffffffffff"))

    outcome = await _configure(_service(repo), ours, dry_run=True)

    assert outcome.dry_run is True


async def test_two_locations_of_one_customer_on_one_site_each_manage_their_own(
    controller,
) -> None:
    org = uuid.uuid4()
    repo = ScopedRepository()
    lobby = repo.add(_row(org))
    spa = repo.add(_row(org, guest_ssid_name="Staff"))
    service = _service(repo)

    await _configure(service, lobby)
    (lobby_portal_id,) = controller.portals
    lobby_portal = copy.deepcopy(controller.portals[lobby_portal_id])
    spa_outcome = await _configure(service, spa)

    assert _outcomes(spa_outcome)["portal"] == "created"
    assert len(controller.portals) == 2
    # B never wrote A's portal...
    assert controller.portals[lobby_portal_id] == lobby_portal
    # ...never duplicated or removed the shared pre-auth entry...
    urls = [p.get("url") for p in controller.access_control["preAuthAccessPolicies"]]
    assert urls.count("auth.wyfyguest.com") == 1
    assert "pms.hotel.example" in urls
    # ...and A is still exactly right afterwards.
    again = await _configure(service, lobby)
    assert set(_outcomes(again).values()) == {"unchanged"}


async def test_the_same_ssid_twice_in_one_organization_is_refused(controller) -> None:
    org = uuid.uuid4()
    repo = ScopedRepository()
    repo.add(_row(org))
    second = repo.add(_row(org))
    with pytest.raises(GuestSsidInUseError):
        await _configure(_service(repo), second)
    assert controller.requests == []


async def test_the_platform_variant_reaches_any_tenant_and_is_audited_as_such(
    controller,
) -> None:
    repo = ScopedRepository()
    row = repo.add(_row(uuid.uuid4()))
    audit = FakeAuditWriter()

    outcome = await _service(repo, audit).configure_platform_controller(
        row.id, actor_user_id=uuid.uuid4(), dry_run=False
    )

    assert outcome.ok is True
    assert audit.entries[-1]["event_metadata"]["platform_action"] is True
    # Written from the row's own identity, not the caller's.
    assert outcome.portal_url_host_and_query.count(str(row.organization_id)) == 1


# ============================================================================
# The HTTP surface
# ============================================================================


def test_the_request_body_is_strict() -> None:
    with pytest.raises(ValidationError):
        ControllerConfigureRequest.model_validate({})  # dry_run is required
    with pytest.raises(ValidationError):
        ControllerConfigureRequest.model_validate({"dryRun": False})
    with pytest.raises(ValidationError):
        ControllerConfigureRequest.model_validate(
            {"dry_run": True, "site_id": "someone-elses-site"}
        )
    parsed = ControllerConfigureRequest.model_validate({"dry_run": True})
    assert parsed.take_over_ssid_portal is False


def _route(app, path: str):
    return next(
        r
        for r in app.routes
        if getattr(r, "path", None) == path and "POST" in getattr(r, "methods", set())
    )


def _calls(dependant) -> set:
    found = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        found |= _calls(d)
    return found


def _closure_values(route) -> list:
    values = []
    for dep in _calls(route.dependant):
        for cell in getattr(dep, "__closure__", None) or ():
            values.append(cell.cell_contents)
    return values


def test_both_configure_controller_routes_are_master_only() -> None:
    """Both routes are GLOBAL-scoped, and the by-id one still resolves the
    caller's organization.

    ## This test used to assert the opposite, and the assertion was stale

    It was written as ``test_the_routes_are_scoped_as_their_audiences_require``
    and required ``ScopeType.GLOBAL`` to be **absent** from
    ``POST /network-integrations/{integration_id}/configure-controller``,
    because that route was the *customer* half of a two-audience design.

    There is no customer audience in this domain any more. ``router``'s own
    module docstring states the product decision in the owner's words --
    "customer dashboard se tp link hatao, sab master dashboard se hoga" --
    and spells out the mechanism: ``RequirePermission`` with no ``scope=``
    resolves its scope from whatever ``X-Organization-Id`` the *caller*
    sent, so an Organization Owner holding the key at ORGANIZATION scope
    satisfied it, which is how eighteen of these routes were reachable from
    a venue admin's session. ``rbac.seed`` retired the non-GLOBAL grants to
    match (``RETIRED_NON_GLOBAL_MODULES``), and
    ``test_network_integration.py::TestEveryRouteRequiresPermission
    ::test_every_route_on_router_requires_global_scope`` asserts the rule
    for all thirty routes.

    So this assertion did not describe a guarantee that had been lost -- it
    described a design that had been deliberately replaced, and it
    contradicted three other places that all agree with each other. It is
    rewritten to the current intent rather than deleted, because the rest
    of what it pins is still worth pinning.

    ## What is still being pinned, and why each line earns its place

    * **Both routes name the permission key.** A route with no
      ``RequirePermission`` at all would still pass a GLOBAL-only check
      vacuously, since there would be no closure to look in.
    * **Both are GLOBAL.** This is the narrower, per-route restatement of
      the structural rule, kept here so that a change to *this pair*
      fails in the file somebody editing autoconfig is actually reading.
    * **The by-id route declares ``CurrentOrganization``.** This is the
      path-id defect class -- a route that reads a resource by path id and
      never resolves the caller's organization hands ``None`` to the
      service, and ``None`` means "platform caller, no filter". Declaring
      it is what makes the service-layer comparison possible at all.
    """
    from app.domains.rbac.dependencies import CurrentOrganization
    from app.domains.rbac.enums import ScopeType
    from app.main import create_app

    app = create_app()
    by_id = _route(
        app, "/api/v1/network-integrations/{integration_id}/configure-controller"
    )
    platform = _route(
        app,
        "/api/v1/network-integrations/platform/integrations/{integration_id}/configure-controller",
    )
    assert CurrentOrganization in _calls(by_id.dependant)
    assert "network_integrations.update" in _closure_values(by_id)
    assert ScopeType.GLOBAL in _closure_values(by_id)
    assert ScopeType.GLOBAL in _closure_values(platform)
    assert "network_integrations.update" in _closure_values(platform)


async def test_the_customer_route_hands_the_callers_organization_to_the_service() -> (
    None
):
    calls: list[dict[str, Any]] = []

    class _Recording:
        async def configure_controller(self, integration_id, **kwargs):
            calls.append({"integration_id": integration_id, **kwargs})
            return SimpleNamespace(
                integration_id=integration_id,
                dry_run=True,
                ok=True,
                changed=False,
                steps=(),
                portal_id=None,
                guest_ssid_id=None,
                portal_url_scheme="https",
                portal_url_host_and_query="auth.wyfyguest.com/portal?x=1",
                pre_auth_host="auth.wyfyguest.com",
            )

    org, integration_id = uuid.uuid4(), uuid.uuid4()
    await router_module.configure_integration_controller(
        request=SimpleNamespace(state=SimpleNamespace(request_id="r")),
        integration_id=integration_id,
        payload=ControllerConfigureRequest(dry_run=True, take_over_ssid_portal=True),
        actor=None,
        requesting_organization_id=org,
        service=_Recording(),
    )
    assert calls == [
        {
            "integration_id": integration_id,
            "actor_user_id": None,
            "requesting_organization_id": org,
            "dry_run": True,
            "take_over_ssid_portal": True,
        }
    ]

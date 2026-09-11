"""Automatic external-portal configuration over the Open API.

Every payload the fake controller serves below is shaped from the OpenAPI
document **Omada Software Controller 5.15.24.19 serves about itself**
(``GET /v3/api-docs`` on our EC2 controller, read 2026-09-12) -- the same
schema names are cited on each builder -- so a test passing here means the
code handles what that firmware documents it returns. It still does not mean
the controller accepts what we send: none of these writes has been made
against real hardware.

What these pin, in order of how badly each would hurt a venue if it broke:

* a refused run (SSID bound to somebody else's portal) writes NOTHING;
* take-over touches only the SSID list of the foreign portal;
* Pre-Authentication Access is merged, never replaced -- every existing entry
  survives with its ``idInt``;
* a dry run makes zero write calls;
* a second run is all ``unchanged`` and writes nothing;
* a create is never replayed after a timeout;
* no operator password appears in a report, a message or a ``repr``.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import httpx
import pytest
from omada_support import (
    ALL_SECRETS,
    CLIENT_ID,
    CLIENT_SECRET,
    OMADAC_ID,
    FakeOmadaController,
    envelope,
    make_creds,
    no_sleep,
    paged,
)
from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    ControllerSsid,
    PortalSetupOutcome,
    PortalSetupSpec,
)
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.client import OmadaHttpClient
from wyfy_device_gateway.omada.errors import (
    OmadaPermissionDeniedError,
    OmadaSiteNotFoundError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.omada.portal_setup import (
    auth_timeout_setting,
    host_of,
    merged_access_control,
    portal_setting_from_detail,
    resolve_ssid,
)
from wyfy_device_gateway.omada.types import OmadaEnvelope

SITE_ID = "6aa3913c3ee1605f71ac35a1"
SSID_ID = "6aa39c6f3ee1605f71ac3622"
OTHER_SSID_ID = "6aa39c6f3ee1605f71ac3699"
ROUTER_ID = "9d7c1f5e-1c55-4e8b-9f61-2a9c1a0c7e11"
INTEGRATION_ID = "3f0e2b1c-8a5d-4d7e-9b2a-1c0d9e8f7a6b"
PORTAL_HOST = "auth.wyfyguest.com"
PORTAL_URL = (
    f"{PORTAL_HOST}/portal?organizationId=11111111-1111-1111-1111-111111111111"
    "&locationId=22222222-2222-2222-2222-222222222222"
    f"&routerId={ROUTER_ID}&netProvider=omada"
)
PORTAL_NAME = "Wyfy Guest - Lobby (3f0e2b1c)"
OPERATOR_NAME = "wyfy-3f0e2b1c8a5d"
NEW_OPERATOR_PASSWORD = "Gen3rated-Operator-Password-XYZ123"  # noqa: S105


def make_spec(**overrides: Any) -> PortalSetupSpec:
    fields: dict[str, Any] = {
        "site_id": SITE_ID,
        "portal_name": PORTAL_NAME,
        "portal_url_scheme": "https",
        "portal_url": PORTAL_URL,
        "ownership_query": ("routerId", ROUTER_ID),
        "pre_auth_host": PORTAL_HOST,
        "auth_timeout_minutes": 60,
        "operator_name": OPERATOR_NAME,
        "operator_note": (
            f"Managed by Wyfy Guest for integration {INTEGRATION_ID}. "
            "Do not edit or delete."
        ),
        "operator_marker": INTEGRATION_ID,
        "guest_ssid_id": None,
        "guest_ssid_name": "WyfyGuest",
        "create_operator_if_missing": True,
        "new_operator_password": NEW_OPERATOR_PASSWORD,
        "take_over_ssid_portal": False,
        "dry_run": False,
    }
    fields.update(overrides)
    return PortalSetupSpec(**fields)


# --- spec-shaped payloads (5.15.24.19 schema names in each docstring) -------


def portal_summary(detail: dict[str, Any]) -> dict[str, Any]:
    """``PortalResOpenApiVO``: id, name, enable, ssidList, networkList,
    authType, hotspotTypes."""
    return {
        "id": detail["id"],
        "name": detail["name"],
        "enable": detail["enable"],
        "ssidList": list(detail.get("ssidList") or []),
        "networkList": list(detail.get("networkList") or []),
        "authType": detail["authType"],
        "hotspotTypes": list((detail.get("hotspot") or {}).get("enabledTypes") or []),
    }


def external_portal_detail(
    portal_id: str,
    *,
    name: str = PORTAL_NAME,
    server_url: str = PORTAL_URL,
    ssids: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """``PortalDetailResOpenApiVO`` for an External Portal Server portal."""
    detail = {
        "id": portal_id,
        "name": name,
        "enable": True,
        "ssidList": [SSID_ID] if ssids is None else ssids,
        "networkList": [],
        "authType": 4,
        "authTimeout": {"authTimeout": 2},
        "httpsRedirectEnable": True,
        "landingPage": 1,
        "externalPortal": {
            "hostType": 2,
            "serverUrlScheme": "https",
            "serverUrl": server_url,
        },
    }
    detail.update(extra)
    return detail


def voucher_portal_detail(portal_id: str, ssids: list[str]) -> dict[str, Any]:
    """A venue's own Hotspot (voucher) portal -- ``authType`` 11 -- carrying
    settings a take-over must hand back untouched."""
    return {
        "id": portal_id,
        "name": "Front Desk Vouchers",
        "enable": True,
        "ssidList": ssids,
        "networkList": ["net-9"],
        "authType": 11,
        "authTimeout": {"authTimeout": 0, "customTimeout": 3, "customTimeoutUnit": 3},
        "httpsRedirectEnable": False,
        "landingPage": 2,
        "landingUrlScheme": "https",
        "landingUrl": "hotel.example/welcome",
        "hotspot": {"enabledTypes": [3, 6]},
        "sms": {
            "sid": "AC-venue-sid",
            "authToken": "venue-twilio-token",
            "phoneNum": "+15550100",
            "maxVerificationCodeEnable": True,
            "maxVerificationCodeTimes": 3,
            "authTimeout": {"authTimeout": 6},
            "countryCode": "+1",
        },
    }


def access_control(
    *, enabled: bool = False, policies: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """``PortalAccessControlOpenApiVO``."""
    return {
        "preAuthAccessEnable": enabled,
        "preAuthAccessPolicies": (
            [
                {"idInt": 1, "type": 1, "ip": "10.20.0.0", "subnetMask": 16},
                {"idInt": 2, "type": 2, "url": "pms.hotel.example"},
            ]
            if policies is None
            else policies
        ),
        "freeAuthClientEnable": True,
        "freeAuthClientPolicies": [
            {"idInt": 7, "type": 4, "clientMac": "AA-BB-CC-00-11-22"}
        ],
    }


class PortalController(FakeOmadaController):
    """A fake controller with the state these operations read and write.

    Writes land in ``self.portals`` / ``self.access_control`` /
    ``self.operators`` so a second run sees what the first one did -- which
    is the only way an idempotency test means anything.
    """

    def __init__(self) -> None:
        super().__init__()
        self.sites = [{"siteId": SITE_ID, "name": "wyfyguest", "type": 0}]
        self.wlans = [{"wlanId": "wlan-1", "name": "Default"}]
        self.ssids = [
            {"ssidId": SSID_ID, "name": "WyfyGuest", "band": 3, "security": 0},
            {"ssidId": OTHER_SSID_ID, "name": "Staff", "band": 3, "security": 3},
        ]
        self.portals: dict[str, dict[str, Any]] = {}
        self.access_control: dict[str, Any] = access_control()
        self.operators: dict[str, dict[str, Any]] = {}
        #: ``(method, path_suffix) -> (errorCode, msg)`` to refuse a write.
        self.refuse: dict[tuple[str, str], tuple[int, str]] = {}
        #: ``(method, path_suffix)`` to answer with a transport timeout.
        self.timeout_on: set[tuple[str, str]] = set()
        self._next_id = 100

    # -- helpers -------------------------------------------------------------

    def writes(self) -> list[tuple[str, str]]:
        return [
            (r.method, r.url.path)
            for r in self.requests
            if r.method in {"POST", "PATCH", "PUT", "DELETE"}
            and not r.url.path.endswith("/api/v2/hotspot/login")
            and r.url.path != "/openapi/authorize/token"
        ]

    def _new_id(self) -> str:
        self._next_id += 1
        return f"6aa3a0{self._next_id:018x}"

    # -- operator login ---------------------------------------------------

    def _login_response(self, body: Any) -> httpx.Response:
        self.login_count += 1
        name = body.get("name") if isinstance(body, dict) else None
        password = body.get("password") if isinstance(body, dict) else None
        known = {op["name"]: op["password"] for op in self.operators.values()}
        if known.get(name) == password and password:
            return httpx.Response(
                200,
                json=envelope({"token": "csrf-token-value-0123456789"}),
                headers=[("set-cookie", "TPOMADA_SESSIONID=abc; Path=/")],
            )
        return httpx.Response(
            200, json=envelope(error_code=-30109, msg="Invalid operator.")
        )

    # -- Open API resources ----------------------------------------------

    def _resource_response(self, request: httpx.Request, path: str) -> httpx.Response:
        method = request.method
        base = f"/openapi/v1/{OMADAC_ID}/sites"
        body = json.loads(request.content) if request.content else None

        for (refuse_method, suffix), (code, msg) in self.refuse.items():
            if method == refuse_method and path.endswith(suffix):
                return httpx.Response(200, json=envelope(error_code=code, msg=msg))
        for timeout_method, suffix in self.timeout_on:
            if method == timeout_method and path.endswith(suffix):
                raise httpx.ReadTimeout("timed out", request=request)

        if path == base and method == "GET":
            return httpx.Response(200, json=envelope(paged(self.sites)))
        site = f"{base}/{SITE_ID}"
        if path == f"{site}/wireless-network/wlans":
            return httpx.Response(200, json=envelope(self.wlans))
        if path == f"{site}/wireless-network/wlans/wlan-1/ssids":
            return httpx.Response(200, json=envelope(paged(self.ssids)))
        if path == f"{site}/portals" and method == "GET":
            return httpx.Response(
                200, json=envelope([portal_summary(p) for p in self.portals.values()])
            )
        if path == f"{site}/portal" and method == "POST":
            for required in (
                "authTimeout",
                "authType",
                "enable",
                "httpsRedirectEnable",
                "landingPage",
                "name",
            ):
                assert required in body, f"addPortal body lacks required {required}"
            portal_id = self._new_id()
            detail = copy.deepcopy(body)
            detail["id"] = portal_id
            # The response side re-spells the timeout (AuthTimeOpenApiVO).
            detail["authTimeout"] = {"authTimeout": 0, **body["authTimeout"]}
            self.portals[portal_id] = detail
            return httpx.Response(200, json={"errorCode": 0, "msg": "Success."})
        if path.startswith(f"{site}/portal/"):
            portal_id = path.rsplit("/", 1)[1]
            if method == "GET":
                return httpx.Response(200, json=envelope(self.portals[portal_id]))
            if method == "PATCH":
                for required in (
                    "authTimeout",
                    "authType",
                    "enable",
                    "httpsRedirectEnable",
                    "landingPage",
                    "name",
                ):
                    assert required in body, f"modifyPortal body lacks {required}"
                updated = copy.deepcopy(body)
                updated["id"] = portal_id
                updated["authTimeout"] = {"authTimeout": 0, **body["authTimeout"]}
                self.portals[portal_id] = updated
                return httpx.Response(200, json={"errorCode": 0, "msg": "Success."})
        if path == f"{site}/setting/access-control":
            if method == "GET":
                return httpx.Response(200, json=envelope(self.access_control))
            if method == "PATCH":
                assert "preAuthAccessEnable" in body and "freeAuthClientEnable" in body
                self.access_control = copy.deepcopy(body)
                for policy in self.access_control["preAuthAccessPolicies"]:
                    policy.setdefault("idInt", self._next_id)
                    self._next_id += 1
                return httpx.Response(200, json=envelope(self.access_control))
        if path == f"{site}/hotspot/operators":
            if method == "GET":
                rows = [
                    {**op, "sites": [{"id": SITE_ID, "name": "wyfyguest"}]}
                    for op in self.operators.values()
                ]
                return httpx.Response(200, json=envelope(paged(rows)))
            if method == "POST":
                operator_id = self._new_id()
                self.operators[operator_id] = {"id": operator_id, **body}
                return httpx.Response(200, json=envelope({}))
        if path.startswith(f"{site}/hotspot/operators/") and method == "PATCH":
            operator_id = path.rsplit("/", 1)[1]
            self.operators[operator_id] = {"id": operator_id, **body}
            return httpx.Response(200, json=envelope(""))
        return httpx.Response(404)


def _adapter(controller: PortalController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(transport=controller.transport(), sleep=no_sleep)


def _creds(*, with_operator: bool = False, password: str | None = None):
    if not with_operator:
        return make_creds()
    return make_creds(
        username=OPERATOR_NAME, password=password or NEW_OPERATOR_PASSWORD
    )


def _by_step(report) -> dict[str, Any]:
    return {step.step: step for step in report.steps}


# ============================================================================
# Happy path, and idempotency
# ============================================================================


async def test_a_fresh_site_is_fully_configured_in_one_run():
    controller = PortalController()
    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    steps = _by_step(report)
    assert report.block is None
    assert steps["portal"].outcome is PortalSetupOutcome.CREATED
    assert steps["pre_auth_access"].outcome is PortalSetupOutcome.CREATED
    assert steps["hotspot_operator"].outcome is PortalSetupOutcome.CREATED
    assert report.guest_ssid_id == SSID_ID
    assert report.operator_credentials_set is True
    assert report.portal_id in controller.portals

    # The portal: External Portal Server, URL host type, scheme and URL split
    # exactly as ExternalServerPortalSetting wants them.
    body = controller.body_for(f"/sites/{SITE_ID}/portal")
    assert body["authType"] == 4
    assert body["externalPortal"] == {
        "hostType": 2,
        "serverUrlScheme": "https",
        "serverUrl": PORTAL_URL,
    }
    assert "://" not in body["externalPortal"]["serverUrl"]
    assert body["ssidList"] == [SSID_ID]
    assert body["authTimeout"] == {"customTimeout": 60, "customTimeoutUnit": 1}

    # The operator: Hotspot Operator schema, this site only, role 0.
    operator_body = controller.body_for(f"/sites/{SITE_ID}/hotspot/operators")
    assert operator_body["name"] == OPERATOR_NAME
    assert operator_body["password"] == NEW_OPERATOR_PASSWORD
    assert operator_body["selectedSites"] == [SITE_ID]
    assert operator_body["operatorRoleType"] == 0
    assert INTEGRATION_ID in operator_body["note"]


async def test_the_second_run_changes_nothing():
    controller = PortalController()
    adapter = _adapter(controller)
    await adapter.configure_external_portal(_creds(), make_spec())
    writes_after_first = len(controller.writes())

    # The caller now holds the operator login it was given, and the id it was
    # told -- exactly what the backend persists after the first run.
    report = await adapter.configure_external_portal(
        _creds(with_operator=True),
        make_spec(guest_ssid_id=SSID_ID, new_operator_password=None),
    )

    assert {s.outcome for s in report.steps} == {PortalSetupOutcome.UNCHANGED}
    assert len(controller.writes()) == writes_after_first
    assert report.operator_credentials_set is False


async def test_a_dry_run_makes_no_write_call_at_all():
    controller = PortalController()
    controller.portals["p-ours"] = external_portal_detail(
        "p-ours", server_url=PORTAL_URL.replace("netProvider=omada", "netProvider=x")
    )

    report = await _adapter(controller).configure_external_portal(
        _creds(), make_spec(dry_run=True, new_operator_password=None)
    )

    assert controller.writes() == []
    steps = _by_step(report)
    assert report.dry_run is True
    assert steps["portal"].outcome is PortalSetupOutcome.UPDATED
    assert steps["portal"].message.startswith("Would update")
    assert steps["pre_auth_access"].outcome is PortalSetupOutcome.CREATED
    assert steps["hotspot_operator"].outcome is PortalSetupOutcome.CREATED
    assert report.operator_credentials_set is False


# ============================================================================
# Our portal: recognised, and repaired only where it drifted
# ============================================================================


async def test_a_drifted_url_is_patched_and_venue_tuning_is_kept():
    controller = PortalController()
    controller.portals["p-ours"] = external_portal_detail(
        "p-ours",
        name="Renamed by the venue",
        server_url=f"{PORTAL_HOST}/old?routerId={ROUTER_ID}",
        httpsRedirectEnable=True,
        landingPage=2,
        landingUrlScheme="https",
        landingUrl="hotel.example",
    )

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    step = _by_step(report)["portal"]
    assert step.outcome is PortalSetupOutcome.UPDATED
    assert "externalPortal.serverUrl" in step.details["drift"]
    assert report.portal_id == "p-ours"
    # Recognised by routerId in its URL although its name was edited -- so no
    # second portal was created next to it.
    assert len(controller.portals) == 1
    patched = controller.portals["p-ours"]
    assert patched["externalPortal"]["serverUrl"] == PORTAL_URL
    assert patched["name"] == PORTAL_NAME
    # What the venue tuned on the portal is not drift and is sent back as-is.
    assert patched["httpsRedirectEnable"] is True
    assert patched["landingPage"] == 2
    assert patched["landingUrl"] == "hotel.example"
    # The preset timeout (2 = 1 hour) went back as the same duration.
    assert controller.body_for("/portal/p-ours")["authTimeout"] == {
        "customTimeout": 1,
        "customTimeoutUnit": 2,
    }


async def test_another_integrations_portal_on_the_same_site_is_not_ours():
    """Two locations of one customer on one site: each only ever sees its own
    portal as ``ours``, because ownership keys on the routerId in the URL."""
    controller = PortalController()
    other_url = PORTAL_URL.replace(ROUTER_ID, "00000000-0000-0000-0000-00000000beef")
    controller.portals["p-other"] = external_portal_detail(
        "p-other",
        name="Wyfy Guest - Spa (aaaaaaaa)",
        server_url=other_url,
        ssids=[OTHER_SSID_ID],
    )

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    assert _by_step(report)["portal"].outcome is PortalSetupOutcome.CREATED
    assert controller.portals["p-other"]["externalPortal"]["serverUrl"] == other_url
    assert all("/portal/p-other" not in path for _, path in controller.writes())


# ============================================================================
# The SSID belongs to somebody else's portal
# ============================================================================


async def test_a_foreign_portal_on_the_ssid_blocks_the_run_and_writes_nothing():
    controller = PortalController()
    controller.portals["p-venue"] = voucher_portal_detail("p-venue", [SSID_ID])

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    assert report.block is not None
    assert report.block.kind == "ssid_portal_conflict"
    assert report.block.portal_id == "p-venue"
    assert report.block.portal_name == "Front Desk Vouchers"
    assert report.steps == ()
    assert controller.writes() == []


async def test_take_over_removes_only_the_ssid_from_the_foreign_portal():
    controller = PortalController()
    before = voucher_portal_detail("p-venue", [SSID_ID, OTHER_SSID_ID])
    controller.portals["p-venue"] = copy.deepcopy(before)

    report = await _adapter(controller).configure_external_portal(
        _creds(), make_spec(take_over_ssid_portal=True)
    )

    steps = _by_step(report)
    assert steps["ssid_takeover"].outcome is PortalSetupOutcome.UPDATED
    assert steps["portal"].outcome is PortalSetupOutcome.CREATED

    sent = controller.body_for("/portal/p-venue")
    assert sent["ssidList"] == [OTHER_SSID_ID]
    # Everything else is what the controller returned, re-spelt only where the
    # request schema spells it differently.
    for key in (
        "name",
        "enable",
        "networkList",
        "authType",
        "httpsRedirectEnable",
        "landingPage",
        "landingUrlScheme",
        "landingUrl",
        "hotspot",
    ):
        assert sent[key] == before[key], key
    assert sent["authTimeout"] == {"customTimeout": 3, "customTimeoutUnit": 3}
    assert sent["sms"]["authToken"] == "venue-twilio-token"
    assert sent["sms"]["userLimitEnable"] is True
    assert sent["sms"]["userLimit"] == 3
    assert "maxVerificationCodeEnable" not in sent["sms"]
    assert sent["sms"]["authTimeout"] == {"customTimeout": 1, "customTimeoutUnit": 3}
    # The foreign portal was patched exactly once and never deleted.
    foreign_writes = [
        w for w in controller.writes() if w[1].endswith("/portal/p-venue")
    ]
    assert foreign_writes == [
        ("PATCH", f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/portal/p-venue")
    ]


async def test_if_the_release_fails_our_portal_is_not_attempted():
    controller = PortalController()
    controller.portals["p-venue"] = voucher_portal_detail("p-venue", [SSID_ID])
    controller.refuse[("PATCH", "/portal/p-venue")] = (
        -1001,
        "Invalid request parameters.",
    )

    report = await _adapter(controller).configure_external_portal(
        _creds(), make_spec(take_over_ssid_portal=True)
    )

    steps = _by_step(report)
    assert steps["ssid_takeover"].outcome is PortalSetupOutcome.FAILED
    assert steps["ssid_takeover"].provider_code == -1001
    assert steps["portal"].outcome is PortalSetupOutcome.SKIPPED
    assert not any(
        path.endswith(f"/sites/{SITE_ID}/portal") for _, path in controller.writes()
    )


# ============================================================================
# Pre-Authentication Access: merge, never replace
# ============================================================================


async def test_pre_auth_merge_keeps_every_existing_entry_verbatim():
    controller = PortalController()
    original = copy.deepcopy(controller.access_control)

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    sent = controller.body_for("/setting/access-control")
    assert sent["preAuthAccessEnable"] is True
    assert sent["preAuthAccessPolicies"][:2] == original["preAuthAccessPolicies"]
    assert sent["preAuthAccessPolicies"][2] == {"type": 2, "url": PORTAL_HOST}
    assert sent["freeAuthClientEnable"] is True
    assert sent["freeAuthClientPolicies"] == original["freeAuthClientPolicies"]
    step = _by_step(report)["pre_auth_access"]
    assert step.details["entries_preserved"] == 2
    # It was off: turning it on activates the venue's two entries too, and the
    # report says so instead of letting that be a surprise.
    assert "also activates the 2 entries" in step.message


async def test_an_existing_entry_for_our_host_is_not_added_twice():
    controller = PortalController()
    controller.access_control = access_control(
        enabled=False,
        policies=[{"idInt": 4, "type": 2, "url": "AUTH.wyfyguest.com"}],
    )

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    sent = controller.body_for("/setting/access-control")
    assert sent["preAuthAccessPolicies"] == [
        {"idInt": 4, "type": 2, "url": "AUTH.wyfyguest.com"}
    ]
    assert _by_step(report)["pre_auth_access"].outcome is PortalSetupOutcome.UPDATED


def test_merge_is_a_no_op_when_already_right():
    current = access_control(
        enabled=True, policies=[{"idInt": 1, "type": 2, "url": PORTAL_HOST}]
    )
    body, added, was_enabled, count = merged_access_control(current, PORTAL_HOST)
    assert body is None and added is False and was_enabled is True and count == 1


# ============================================================================
# Hotspot operator
# ============================================================================


async def test_a_stored_operator_that_fails_to_sign_in_is_reported_not_rotated():
    controller = PortalController()

    report = await _adapter(controller).configure_external_portal(
        _creds(with_operator=True, password="wrong-password"),  # noqa: S106
        make_spec(new_operator_password=None),
    )

    step = _by_step(report)["hotspot_operator"]
    assert step.outcome is PortalSetupOutcome.FAILED
    assert "not changed" in step.message
    assert report.operator_credentials_set is False
    assert not any("/hotspot/operators" in path for _, path in controller.writes())


async def test_an_operator_with_our_name_but_not_ours_is_left_alone():
    controller = PortalController()
    controller.operators["op-1"] = {
        "id": "op-1",
        "name": OPERATOR_NAME,
        "password": "venue-pw",
        "note": "front desk",
        "operatorRoleType": 0,
        "selectedSites": [SITE_ID],
    }

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    assert _by_step(report)["hotspot_operator"].outcome is PortalSetupOutcome.FAILED
    assert controller.operators["op-1"]["password"] == "venue-pw"  # noqa: S105
    assert report.operator_credentials_set is False


async def test_our_own_orphaned_operator_is_reset_not_duplicated():
    """An earlier run created the account and the backend never saved its
    password (the request rolled back). The note carries our marker, so this
    run resets it instead of failing forever on a name collision."""
    controller = PortalController()
    controller.operators["op-1"] = {
        "id": "op-1",
        "name": OPERATOR_NAME,
        "password": "lost",
        "note": f"Managed by Wyfy Guest for integration {INTEGRATION_ID}.",
        "operatorRoleType": 0,
        "selectedSites": [SITE_ID],
    }

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    assert _by_step(report)["hotspot_operator"].outcome is PortalSetupOutcome.UPDATED
    assert report.operator_credentials_set is True
    assert len(controller.operators) == 1
    assert controller.operators["op-1"]["password"] == NEW_OPERATOR_PASSWORD


# ============================================================================
# Failure handling
# ============================================================================


async def test_a_permission_refusal_fails_one_step_and_the_rest_still_run():
    controller = PortalController()
    controller.refuse[("PATCH", "/setting/access-control")] = (
        -1005,
        "Operation forbidden.",
    )

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    steps = _by_step(report)
    assert steps["pre_auth_access"].outcome is PortalSetupOutcome.FAILED
    assert steps["pre_auth_access"].provider_code == -1005
    assert "Platform Integration > Open API" in steps["pre_auth_access"].message
    assert steps["portal"].outcome is PortalSetupOutcome.CREATED
    assert steps["hotspot_operator"].outcome is PortalSetupOutcome.CREATED


async def test_a_timed_out_create_is_sent_once_and_later_steps_are_skipped():
    controller = PortalController()
    controller.timeout_on.add(("POST", f"/sites/{SITE_ID}/portal"))

    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())

    posts = [
        w
        for w in controller.writes()
        if w == ("POST", f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/portal")
    ]
    assert len(posts) == 1
    steps = _by_step(report)
    assert steps["portal"].outcome is PortalSetupOutcome.FAILED
    assert steps["pre_auth_access"].outcome is PortalSetupOutcome.SKIPPED
    assert steps["hotspot_operator"].outcome is PortalSetupOutcome.SKIPPED
    assert report.operator_credentials_set is False


async def test_ssid_resolution_failures_block_before_any_write():
    controller = PortalController()
    report = await _adapter(controller).configure_external_portal(
        _creds(), make_spec(guest_ssid_name="NoSuchSSID")
    )
    assert report.block is not None and report.block.kind == "guest_ssid_not_found"
    assert controller.writes() == []


def test_a_name_on_two_ssids_is_ambiguous_not_guessed():
    ssids = [
        ControllerSsid(ssid_id="a", name="Guest"),
        ControllerSsid(ssid_id="b", name="Guest"),
    ]
    ssid_id, block = resolve_ssid(ssids, make_spec(guest_ssid_name="Guest"))
    assert ssid_id is None
    assert block is not None and block.kind == "guest_ssid_ambiguous"
    assert block.match_count == 2


def test_a_stored_id_that_vanished_falls_back_to_the_name():
    ssids = [ControllerSsid(ssid_id="new-id", name="WyfyGuest")]
    ssid_id, block = resolve_ssid(ssids, make_spec(guest_ssid_id="old-id"))
    assert (ssid_id, block) == ("new-id", None)


async def test_a_site_the_app_cannot_see_is_named_as_such():
    controller = PortalController()
    controller.sites = [{"siteId": "some-other-site", "name": "x"}]
    with pytest.raises(OmadaSiteNotFoundError, match="site privileges"):
        await _adapter(controller).configure_external_portal(_creds(), make_spec())
    assert controller.writes() == []


async def test_legacy_credentials_are_refused_before_any_request():
    controller = PortalController()
    with pytest.raises(OmadaUnsupportedApiError, match="Open API"):
        await _adapter(controller).configure_external_portal(
            make_creds(ControllerAuthMode.LEGACY), make_spec()
        )
    assert controller.requests == []


def test_minus_1005_and_minus_1505_are_permission_errors():
    for code in (-1005, -1505):
        error = OmadaHttpClient.translate_envelope_error(
            OmadaEnvelope(error_code=code, msg="Operation forbidden.", result=None)
        )
        assert isinstance(error, OmadaPermissionDeniedError)
        assert error.provider_code == code


# ============================================================================
# Secrets
# ============================================================================


async def test_no_password_or_secret_reaches_the_report():
    controller = PortalController()
    report = await _adapter(controller).configure_external_portal(_creds(), make_spec())
    rendered = repr(report) + json.dumps(
        [
            {"m": s.message, "d": {k: str(v) for k, v in s.details.items()}}
            for s in report.steps
        ]
    )
    for secret in (NEW_OPERATOR_PASSWORD, CLIENT_SECRET, CLIENT_ID, *ALL_SECRETS):
        assert secret not in rendered
    assert NEW_OPERATOR_PASSWORD not in repr(make_spec())


# ============================================================================
# Pure projections
# ============================================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"authTimeout": 1}, {"customTimeout": 30, "customTimeoutUnit": 1}),
        ({"authTimeout": 7}, {"customTimeout": 7, "customTimeoutUnit": 3}),
        (
            {"authTimeout": 0, "customTimeout": 90, "customTimeoutUnit": 1},
            {"customTimeout": 90, "customTimeoutUnit": 1},
        ),
        (None, {"customTimeout": 5, "customTimeoutUnit": 1}),
    ],
)
def test_auth_timeout_is_respelt_for_the_request_schema(value, expected):
    assert (
        auth_timeout_setting(
            value, fallback={"customTimeout": 5, "customTimeoutUnit": 1}
        )
        == expected
    )


def test_the_projection_drops_only_read_only_fields():
    detail = voucher_portal_detail("p", [SSID_ID])
    detail["id"] = "p"
    detail["hotspotRadius"] = {
        "radiusProfileId": "r",
        "authMode": 1,
        "nasId": "n",
        "receiverPortStatus": 1,
        "authTimeout": {"authTimeout": 3},
    }
    body = portal_setting_from_detail(
        detail, fallback_auth_timeout={"customTimeout": 1, "customTimeoutUnit": 2}
    )
    assert "id" not in body
    assert "receiverPortStatus" not in body["hotspotRadius"]
    assert body["hotspotRadius"]["authTimeout"] == {
        "customTimeout": 2,
        "customTimeoutUnit": 2,
    }
    assert detail["sms"]["maxVerificationCodeEnable"] is True  # input untouched


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("auth.wyfyguest.com", "auth.wyfyguest.com"),
        ("https://Auth.WyfyGuest.com/portal?x=1", "auth.wyfyguest.com"),
        ("auth.wyfyguest.com:443", "auth.wyfyguest.com"),
        ("auth.wyfyguest.com:8443", "auth.wyfyguest.com:8443"),
        ("", None),
    ],
)
def test_host_of(value, expected):
    assert host_of(value) == expected

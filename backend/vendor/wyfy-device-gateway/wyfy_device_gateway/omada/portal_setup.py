"""Configure one site's external captive portal through the Open API.

Everything a venue used to do by hand on the controller before a Wyfy Guest
guest could get online -- and the three things the runbook calls easiest to
get wrong -- done as one idempotent operation:

1. **Portal.** An *External Portal Server* portal (``authType`` 4, host type
   URL) whose server URL is exactly the one the caller computed, bound to the
   integration's guest SSID. Created when absent, patched when it has drifted,
   left alone when it is right.
2. **Pre-Authentication Access.** Enabled, with a URL entry for the portal
   host. Without it every pre-auth HTTPS request -- our portal included --
   times out (measured on hardware, see ``HARDWARE-FINDINGS.md``).
3. **Hotspot operator.** Guest authorization (``extPortal/auth``) takes an
   operator login in both auth modes. If the caller holds none, a dedicated
   account is created with a password the caller generated; if it holds one,
   that login is proven, never replaced.

## The rules that make it safe to press twice, and on a shared controller

* **Plan, then write.** Every read happens first. A refusal (SSID not found,
  SSID bound to somebody else's portal) is decided before a single write, so
  a refused run has changed nothing.
* **Only our portal is ever written** -- identified by its exact name *or* by
  the caller's ownership pair (``spec.ownership_query``) in its server URL's
  query. The backend's pair is ``routerId=<fleet device id>``, unique per
  integration, so two locations of one customer on one site never mistake
  each other's portal for their own. A foreign portal is written in exactly
  one case: ``take_over_ssid_portal``, and then only its ``ssidList`` loses
  our SSID; every other field is sent back as the controller returned it.
* **Pre-Authentication Access is merge-only.** The PATCH is full-config (the
  spec says "the full configuration parameters should be passed in"), so the
  body is the controller's own GET result with our entry appended. Every
  existing entry is sent back verbatim, ``idInt`` included, which is what the
  spec asks for ("Except for newly added policies, this parameter should be
  retained"). Nothing is ever removed, so configuring location B cannot take
  away what location A needed.
* **Creates are sent once.** ``retry_on_transport_error=False`` on every
  ``POST``: a timed-out create may or may not have happened, and replaying it
  is how one click becomes two portals. The next run re-reads and converges.
* **No secret in any report.** Operator passwords go out in a request body and
  nowhere else; the list endpoint *returns* passwords and they are never read.

## Sourcing -- VERIFIED against two primary TP-Link documents

Every path and field below is taken from TP-Link's OpenAPI 3.0.1
specification, in two copies that agree on everything used here:

* the cloud Open API gateway's spec,
  <https://use1-omada-northbound.tplinkcloud.com/v3/api-docs> (1918 paths);
* **the spec Omada Software Controller 5.15.24.19 serves about itself**, at
  ``GET /v3/api-docs`` (1224 paths, unauthenticated), read 2026-09-12 from our
  own EC2 controller. This is the firmware the first venues will run.

Operations used, all present in both: ``getPortalList``, ``getPortalDetail``,
``addPortal``, ``modifyPortal``, ``getAccessControl``, ``modifyAccessControl``,
``getHotspotOperatorList``, ``createHotspotOperator``,
``modifyHotspotOperator``, plus the existing site and SSID reads.

Deliberately NOT used: ``getPortalCandidates``
(``POST .../hotspot/portal/candidates``) **does not exist on 5.15.24.19**, and
neither does ``GET /openapi/v2/.../wireless-network/ssids``. SSIDs are
resolved through the WLAN-group walk in ``sites.py``, which both firmwares
serve (5.15 rows carry ``wlanId``/``ssidId`` and no ``id``; ``sites.py``
already falls back).

## Honest scope -- what is NOT verified

None of the writes here has been sent to a real controller. The paths and
body shapes are the controller's own spec; what the spec cannot say is:

* whether ``modifyPortal`` treats fields it was not sent
  (``portalCustomize``, ``pageType``, ``importedPortalPage`` -- absent from
  the detail response, so they cannot be echoed) as "unchanged" or as
  "reset". That matters only for take-over of a *foreign* portal with a
  customised local page.

  **Downgraded 2026-09-12: the evidence now points at RESET, not unchanged.**
  It is no longer an even bet. TP-Link's own spec, on the very schema
  ``modifyPortal`` takes, says of ``pageType``: "Page type, should be a
  value as follows: 1: Use default page, 2: use uploaded page. **When
  [pageType] is null, it defaults to 1**" -- and ``ImportedPortalPageOpenApiVO``
  is described as "Imported portal page, required when parameter [pageType]
  is 2". A body with no ``pageType`` is therefore documented to *mean* "use
  default page", which on a portal currently set to 2 is a reset that also
  strands its uploaded page. Two further tells point the same way: the
  ``PortalSetting`` schema marks six fields required (``authTimeout``,
  ``authType``, ``enable``, ``httpsRedirectEnable``, ``landingPage``,
  ``name``), which is a whole-object replace wearing a PATCH's clothes; and
  ``getPortalDetail`` really does omit all three fields, confirmed against
  ``PortalDetailResOpenApiVO`` in the published spec, so no read-modify-write
  can preserve them.

  This is a documented *default*, not a documented *PATCH semantic*, and the
  schema is shared with ``addPortal`` where "defaults to 1" is unremarkable.
  So it is not proof. But ``take_over_ssid_portal`` should be treated as
  unsafe against a portal with an uploaded page until it is measured:
  ``OMADA_HARDWARE_VERIFICATION.md`` test 4, which is a must-fix if it
  confirms. Note ``GET .../portal/{portalId}/customization`` exists and is
  what a pre-write snapshot should capture.
* whether an operator with ``operatorRoleType`` 0 (Administrator) is the
  least privilege that can call ``extPortal/auth``. 0 is what the one
  hardware-proven operator had (``HARDWARE-FINDINGS.md``); Viewer (1) was
  never tried.

  **Still INFERRED after research.** TP-Link's user guide says only that for
  a Hotspot Manager operator the "Admin role has read and write permissions"
  and the "Viewer role has read-only permissions", and elsewhere that
  operator accounts "can only be used to remotely log in to the Hotspot
  Manager system and manage vouchers and local users for specified sites" --
  neither of which says whether ``extPortal/auth`` is gated on the role.
  Nothing in the Open API spec's ``Hotspot Operator`` schema says more than
  "0: Administrator; 1: Viewer" either. Creating role 0 is the safe side of
  an unresolved question and stays. Do not "optimise" it down to 1 on the
  strength of least-privilege instinct; ``OMADA_HARDWARE_VERIFICATION.md``
  test 3 is how that would be earned.
"""

from __future__ import annotations

import copy
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..controller_contract import (
    ControllerSsid,
    PortalSetupBlock,
    PortalSetupOutcome,
    PortalSetupReport,
    PortalSetupSpec,
    PortalSetupStep,
)
from . import sites as sites_module
from .client import OmadaHttpClient
from .errors import (
    OmadaAuthError,
    OmadaConnectionError,
    OmadaError,
    OmadaInvalidControllerError,
    OmadaRateLimitedError,
    OmadaSessionExpiredError,
    OmadaSiteNotFoundError,
    OmadaTimeoutError,
    OmadaTlsPinMismatchError,
    OmadaTlsTrustError,
)
from .redaction import sanitize_detail
from .types import coerce_bool, coerce_int, coerce_str, extract_page

# --- paths (VERIFIED: both specs, see module docstring) ---------------------

PORTALS_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/portals"
PORTAL_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/portal/{portal_id}"
ADD_PORTAL_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/portal"
ACCESS_CONTROL_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/setting/access-control"
OPERATORS_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/hotspot/operators"
OPERATOR_PATH = (
    "/openapi/v1/{omadac_id}/sites/{site_id}/hotspot/operators/{operator_id}"
)

# --- enum values (VERIFIED: field descriptions in both specs) ---------------

#: ``PortalSetting.authType``: "4: External Portal Server".
AUTH_TYPE_EXTERNAL_PORTAL = 4
#: ``ExternalServerPortalSetting.hostType``: "1: IP; 2: URL". Only URL has a
#: path, and the query string lives in the path (see the backend's
#: ``validators.ExternalPortalUrl``).
HOST_TYPE_URL = 2
#: ``PreAuthAccessPolicyOpenApiVO.type``: "2: URL, and parameter [url] is
#: needed". A URL entry permits the address the name resolves to, not the
#: name (measured, ``HARDWARE-FINDINGS.md``).
PRE_AUTH_POLICY_TYPE_URL = 2
#: ``AuthTimeoutSetting.customTimeoutUnit``: "1: min; 2: hour; 3: day".
AUTH_TIMEOUT_UNIT_MINUTES = 1
#: ``AuthTimeoutSetting.customTimeout`` range for minutes: 1 - 1,000,000.
AUTH_TIMEOUT_MAX_MINUTES = 1_000_000
#: ``PortalSetting.landingPage``: "1: Redirect to the original URL".
LANDING_PAGE_ORIGINAL_URL = 1
#: ``Hotspot Operator.operatorRoleType``: "0: Administrator; 1: Viewer". 0 is
#: the role of the only operator ever proven against ``extPortal/auth``.
OPERATOR_ROLE_ADMINISTRATOR = 0
#: ``PortalSetting.name``: "should contain 1 to 128 characters".
PORTAL_NAME_MAX_LENGTH = 128

#: ``AuthTimeOpenApiVO.authTimeout`` presets (response side) -> the request
#: side's ``(customTimeout, customTimeoutUnit)``. The request schema
#: (``AuthTimeoutSetting``) has no preset field at all, so a portal read back
#: with a preset can only be written back as the same duration spelled out:
#: "1: 30 Minutes; 2: 1 Hour; 3: 2 Hours; 4: 4 Hours; 5: 8 Hours; 6: 1 Day;
#: 7: 7 Days".
_PRESET_AUTH_TIMEOUTS: dict[int, tuple[int, int]] = {
    1: (30, 1),
    2: (1, 2),
    3: (2, 2),
    4: (4, 2),
    5: (8, 2),
    6: (1, 3),
    7: (7, 3),
}
#: Used only when a portal detail carries no timeout at all ("Display when
#: enabled, otherwise no display") and a PATCH still requires one.
_FALLBACK_AUTH_TIMEOUT: dict[str, int] = {"customTimeout": 1, "customTimeoutUnit": 2}

#: The ``PortalSetting`` fields that ``PortalDetailResOpenApiVO`` also
#: returns -- i.e. everything that CAN be echoed back. ``socialLogin`` and
#: ``google`` exist only in the cloud spec; they are echoed when a controller
#: returns them and are simply absent on 5.15.
_ECHOABLE_PORTAL_FIELDS: tuple[str, ...] = (
    "name",
    "enable",
    "ssidList",
    "networkList",
    "authType",
    "authTimeout",
    "httpsRedirectEnable",
    "landingPage",
    "landingUrlScheme",
    "landingUrl",
    "noAuth",
    "simplePassword",
    "hotspot",
    "socialLogin",
    "google",
    "sms",
    "portalFormId",
    "hotspotRadius",
    "externalPortal",
    "externalRadius",
    "ldap",
)

STEP_SSID_TAKEOVER = "ssid_takeover"
STEP_PORTAL = "portal"
STEP_PRE_AUTH_ACCESS = "pre_auth_access"
STEP_HOTSPOT_OPERATOR = "hotspot_operator"

#: Failures after which the controller is not answering us at all -- every
#: later write would fail the same way, so they are reported as not attempted
#: rather than tried.
_LOST_CONTACT: tuple[type[OmadaError], ...] = (
    OmadaTimeoutError,
    OmadaConnectionError,
    OmadaTlsTrustError,
    OmadaTlsPinMismatchError,
    OmadaAuthError,
    OmadaSessionExpiredError,
    OmadaRateLimitedError,
    OmadaInvalidControllerError,
)

VerifyLogin = Callable[[str, str], Awaitable[None]]


# ============================================================================
# Pure helpers (exported for tests)
# ============================================================================


def host_of(value: object) -> str | None:
    """The lowercase host of a URL-ish string, with any scheme, path, query
    and default HTTPS port removed. ``None`` for anything empty."""
    text = coerce_str(value)
    if not text:
        return None
    text = text.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    host = text.split("/", 1)[0].split("?", 1)[0]
    if host.endswith(":443"):
        host = host[: -len(":443")]
    return host.rstrip(".") or None


def _query_of(server_url: object) -> dict[str, list[str]]:
    text = coerce_str(server_url)
    if not text:
        return {}
    if "://" in text:
        text = text.split("://", 1)[1]
    return parse_qs(urlsplit("//" + text).query)


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := coerce_str(item))]


def _safe_name(value: object) -> str:
    """A controller-supplied portal or SSID name, fit to put in a message."""
    return sanitize_detail(coerce_str(value)) or "(unnamed)"


def auth_timeout_setting(value: object, *, fallback: dict[str, int]) -> dict[str, int]:
    """``AuthTimeOpenApiVO`` (what a GET returns) -> ``AuthTimeoutSetting``
    (what a PATCH accepts). The same duration, spelled the only way the
    request schema can spell it."""
    if not isinstance(value, dict):
        return dict(fallback)
    preset = coerce_int(value.get("authTimeout"))
    custom = coerce_int(value.get("customTimeout"))
    unit = coerce_int(value.get("customTimeoutUnit"))
    if preset in (None, 0) and custom is not None and unit is not None:
        return {"customTimeout": custom, "customTimeoutUnit": unit}
    if preset in _PRESET_AUTH_TIMEOUTS:
        amount, preset_unit = _PRESET_AUTH_TIMEOUTS[preset]
        return {"customTimeout": amount, "customTimeoutUnit": preset_unit}
    if custom is not None and unit is not None:
        return {"customTimeout": custom, "customTimeoutUnit": unit}
    return dict(fallback)


def portal_setting_from_detail(
    detail: dict[str, Any], *, fallback_auth_timeout: dict[str, int]
) -> dict[str, Any]:
    """Project a ``getPortalDetail`` result onto the ``PortalSetting`` a
    ``modifyPortal`` accepts, changing nothing it can carry.

    Three response/request differences exist in both specs and are the only
    transformations made:

    * ``authTimeout`` objects (top level, ``sms``, ``hotspotRadius``) -- see
      :func:`auth_timeout_setting`;
    * ``sms.maxVerificationCodeEnable``/``maxVerificationCodeTimes`` are
      ``userLimitEnable``/``userLimit`` on the request side (identical field
      descriptions in both specs);
    * ``receiverPortStatus`` on the two RADIUS objects is read-only status
      with no request counterpart, and is dropped.
    """
    body: dict[str, Any] = {}
    for key in _ECHOABLE_PORTAL_FIELDS:
        if key in detail and detail[key] is not None:
            body[key] = copy.deepcopy(detail[key])
    body["authTimeout"] = auth_timeout_setting(
        detail.get("authTimeout"), fallback=fallback_auth_timeout
    )
    sms = body.get("sms")
    if isinstance(sms, dict):
        if "maxVerificationCodeEnable" in sms:
            sms["userLimitEnable"] = sms.pop("maxVerificationCodeEnable")
        if "maxVerificationCodeTimes" in sms:
            sms["userLimit"] = sms.pop("maxVerificationCodeTimes")
        if "authTimeout" in sms:
            sms["authTimeout"] = auth_timeout_setting(
                sms["authTimeout"], fallback=_FALLBACK_AUTH_TIMEOUT
            )
    for key in ("hotspotRadius", "externalRadius"):
        radius = body.get(key)
        if isinstance(radius, dict):
            radius.pop("receiverPortStatus", None)
            if "authTimeout" in radius:
                radius["authTimeout"] = auth_timeout_setting(
                    radius["authTimeout"], fallback=_FALLBACK_AUTH_TIMEOUT
                )
    return body


def _fill_required_portal_fields(body: dict[str, Any]) -> list[str]:
    """``PortalSetting`` requires these; a detail that omitted one cannot be
    written back without a value. Returns the names that had to be filled so
    the report can say so rather than hide it."""
    filled: list[str] = []
    for key, default in (
        ("enable", True),
        ("httpsRedirectEnable", False),
        ("landingPage", LANDING_PAGE_ORIGINAL_URL),
    ):
        if body.get(key) is None:
            body[key] = default
            filled.append(key)
    return filled


def _our_auth_timeout(spec: PortalSetupSpec) -> dict[str, int]:
    minutes = min(max(int(spec.auth_timeout_minutes), 1), AUTH_TIMEOUT_MAX_MINUTES)
    return {"customTimeout": minutes, "customTimeoutUnit": AUTH_TIMEOUT_UNIT_MINUTES}


def _external_portal(spec: PortalSetupSpec) -> dict[str, Any]:
    return {
        "hostType": HOST_TYPE_URL,
        "serverUrlScheme": spec.portal_url_scheme,
        "serverUrl": spec.portal_url,
    }


def new_portal_body(spec: PortalSetupSpec, ssid_id: str) -> dict[str, Any]:
    """``addPortal`` body. Every required ``PortalSetting`` field, and the
    external-portal settings; nothing a local portal page would need."""
    return {
        "name": spec.portal_name,
        "enable": True,
        "ssidList": [ssid_id],
        "networkList": [],
        "authType": AUTH_TYPE_EXTERNAL_PORTAL,
        "authTimeout": _our_auth_timeout(spec),
        "httpsRedirectEnable": False,
        "landingPage": LANDING_PAGE_ORIGINAL_URL,
        "externalPortal": _external_portal(spec),
    }


def portal_drift(
    detail: dict[str, Any], spec: PortalSetupSpec, ssid_id: str
) -> list[str]:
    """The fields of our portal that differ from ``spec``. Empty means
    nothing to do. Deliberately narrow: settings a venue may tune on our
    portal (HTTPS redirect, landing page, timeout) are not drift."""
    drift: list[str] = []
    if coerce_str(detail.get("name")) != spec.portal_name:
        drift.append("name")
    if coerce_bool(detail.get("enable")) is not True:
        drift.append("enable")
    if coerce_int(detail.get("authType")) != AUTH_TYPE_EXTERNAL_PORTAL:
        drift.append("authType")
    external = detail.get("externalPortal")
    external = external if isinstance(external, dict) else {}
    if coerce_int(external.get("hostType")) != HOST_TYPE_URL:
        drift.append("externalPortal.hostType")
    if coerce_str(external.get("serverUrlScheme")) != spec.portal_url_scheme:
        drift.append("externalPortal.serverUrlScheme")
    if coerce_str(external.get("serverUrl")) != spec.portal_url:
        drift.append("externalPortal.serverUrl")
    if ssid_id not in _str_list(detail.get("ssidList")):
        drift.append("ssidList")
    return drift


def updated_portal_body(
    detail: dict[str, Any], spec: PortalSetupSpec, ssid_id: str
) -> dict[str, Any]:
    """``modifyPortal`` body for OUR portal: what it has, with our settings
    laid over it. Other SSIDs a venue bound to it are kept."""
    body = portal_setting_from_detail(
        detail, fallback_auth_timeout=_our_auth_timeout(spec)
    )
    body["name"] = spec.portal_name
    body["enable"] = True
    body["authType"] = AUTH_TYPE_EXTERNAL_PORTAL
    body["externalPortal"] = _external_portal(spec)
    ssids = _str_list(body.get("ssidList"))
    if ssid_id not in ssids:
        ssids.append(ssid_id)
    body["ssidList"] = ssids
    _fill_required_portal_fields(body)
    return body


def released_portal_body(
    detail: dict[str, Any], ssid_id: str
) -> tuple[dict[str, Any], list[str]]:
    """``modifyPortal`` body for a FOREIGN portal on take-over: exactly what
    the controller returned, minus our SSID. Returns ``(body, filled)``."""
    body = portal_setting_from_detail(
        detail, fallback_auth_timeout=_FALLBACK_AUTH_TIMEOUT
    )
    body["ssidList"] = [s for s in _str_list(body.get("ssidList")) if s != ssid_id]
    filled = _fill_required_portal_fields(body)
    return body, filled


def merged_access_control(
    current: dict[str, Any], host: str
) -> tuple[dict[str, Any] | None, bool, bool, int]:
    """``modifyAccessControl`` body, or ``None`` when nothing needs changing.

    Returns ``(body, entry_added, was_enabled, existing_entry_count)``. The
    body is the controller's own GET result with ``preAuthAccessEnable``
    forced on and, if absent, one URL entry for ``host`` appended. Every other
    key and every existing entry is carried through untouched.
    """
    existing = current.get("preAuthAccessPolicies")
    existing = list(existing) if isinstance(existing, list) else []
    wanted = host_of(host)
    has_entry = any(
        isinstance(policy, dict)
        and coerce_int(policy.get("type")) == PRE_AUTH_POLICY_TYPE_URL
        and host_of(policy.get("url")) == wanted
        for policy in existing
    )
    was_enabled = coerce_bool(current.get("preAuthAccessEnable")) is True
    if has_entry and was_enabled:
        return None, False, True, len(existing)
    body = copy.deepcopy(current)
    body["preAuthAccessEnable"] = True
    policies = copy.deepcopy(existing)
    if not has_entry:
        policies.append({"type": PRE_AUTH_POLICY_TYPE_URL, "url": host})
    body["preAuthAccessPolicies"] = policies
    # Both required by the request schema; carried as the controller reported
    # them, and only defaulted when the GET genuinely omitted them.
    if body.get("freeAuthClientEnable") is None:
        body["freeAuthClientEnable"] = False
    if body.get("freeAuthClientPolicies") is None:
        body["freeAuthClientPolicies"] = []
    return body, not has_entry, was_enabled, len(existing)


def resolve_ssid(
    ssids: list[ControllerSsid], spec: PortalSetupSpec
) -> tuple[str | None, PortalSetupBlock | None]:
    """The SSID id to bind, or a block explaining why there is none.

    A stored id that still exists wins. A stored id that has gone (the SSID
    was deleted and re-created) falls back to the stored name, and the caller
    persists whatever id this returns. A name matching more than one SSID is
    refused rather than guessed: binding the wrong one sends a different
    network's guests to this venue's sign-in page.
    """
    if spec.guest_ssid_id:
        for ssid in ssids:
            if ssid.ssid_id == spec.guest_ssid_id:
                return ssid.ssid_id, None
    if spec.guest_ssid_name:
        ids = sorted(
            {s.ssid_id for s in ssids if s.ssid_id and s.name == spec.guest_ssid_name}
        )
        if len(ids) == 1:
            return ids[0], None
        if len(ids) > 1:
            return None, PortalSetupBlock(
                kind="guest_ssid_ambiguous",
                message=(
                    f"{len(ids)} SSIDs on this site are named "
                    f"'{_safe_name(spec.guest_ssid_name)}' (in different WLAN "
                    "groups). Pick the exact guest SSID on this integration, "
                    "then run again. Nothing was changed."
                ),
                match_count=len(ids),
            )
    label = spec.guest_ssid_name or spec.guest_ssid_id or ""
    return None, PortalSetupBlock(
        kind="guest_ssid_not_found",
        message=(
            f"The guest SSID '{_safe_name(label)}' does not exist on this "
            "site. Create it on the controller, or pick an existing SSID on "
            "this integration, then run again. Nothing was changed."
        ),
        match_count=0,
    )


# ============================================================================
# Plan / apply
# ============================================================================


@dataclass
class _WriteResult:
    outcome: PortalSetupOutcome | None = None
    message: str | None = None
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class _Action:
    step: str
    outcome: PortalSetupOutcome
    #: The message when nothing is written (unchanged / refused at planning),
    #: or when the write is merely planned (dry run).
    plan_message: str
    #: The message once the write has been made.
    done_message: str = ""
    #: What a failed write is called in the report ("Could not create ...").
    failure_prefix: str = ""
    write: Callable[[], Awaitable[_WriteResult | None]] | None = None
    details: dict[str, object] = field(default_factory=dict)
    provider_code: int | None = None
    #: Name of an earlier step that must not have failed for this one to run.
    depends_on: str | None = None


async def _portal_detail(
    client: OmadaHttpClient, omadac_id: str, site_id: str, portal_id: str
) -> dict[str, Any]:
    envelope = await client.request(
        "GET",
        PORTAL_PATH.format(omadac_id=omadac_id, site_id=site_id, portal_id=portal_id),
    )
    return envelope.result if isinstance(envelope.result, dict) else {}


async def _list_portals(
    client: OmadaHttpClient, omadac_id: str, site_id: str
) -> list[dict[str, Any]]:
    # ``getPortalList`` answers a bare array, not the paginated grid;
    # ``extract_page`` accepts both.
    envelope = await client.request(
        "GET", PORTALS_PATH.format(omadac_id=omadac_id, site_id=site_id)
    )
    return extract_page(envelope.result)


def _owns(
    summary: dict[str, Any], detail: dict[str, Any] | None, spec: PortalSetupSpec
) -> bool:
    if coerce_str(summary.get("name")) == spec.portal_name:
        return True
    if not detail:
        return False
    external = detail.get("externalPortal")
    if not isinstance(external, dict):
        return False
    if host_of(external.get("serverUrl")) != host_of(spec.portal_url):
        return False
    key, value = spec.ownership_query
    return value in _query_of(external.get("serverUrl")).get(key, [])


async def configure_external_portal(
    client: OmadaHttpClient,
    omadac_id: str,
    spec: PortalSetupSpec,
    *,
    stored_operator: tuple[str, str] | None,
    verify_operator_login: VerifyLogin,
) -> PortalSetupReport:
    """Plan every step from reads, then (unless ``spec.dry_run``) apply them.

    ``stored_operator`` is the ``(name, password)`` the caller already holds,
    or ``None``. ``verify_operator_login`` performs a real hotspot-operator
    login and raises ``OmadaAuthError`` on refusal -- the adapter owns how.

    Raises only for failures during *planning* (the controller unreachable,
    credentials refused, the site invisible to the app). Once writing starts
    every failure is recorded on its step instead, so the caller always gets
    a report saying exactly what was and was not changed.
    """
    site_id = spec.site_id
    paths = {"omadac_id": omadac_id, "site_id": site_id}

    # -- reads ---------------------------------------------------------------
    try:
        await sites_module.get_site(client, omadac_id, site_id)
    except OmadaSiteNotFoundError as exc:
        raise OmadaSiteNotFoundError(
            "This integration's site is not visible to the Open API app: it "
            "was deleted on the controller, or the app's site privileges do "
            "not include it.",
            provider_code=exc.provider_code,
        ) from exc

    ssids = await sites_module.list_ssids(client, omadac_id, site_id)
    ssid_id, block = resolve_ssid(ssids, spec)
    if block is not None or ssid_id is None:
        return PortalSetupReport(dry_run=spec.dry_run, block=block)
    ssid_label = next(
        (_safe_name(s.name) for s in ssids if s.ssid_id == ssid_id), ssid_id
    )

    summaries = await _list_portals(client, omadac_id, site_id)
    details: dict[str, dict[str, Any]] = {}
    for summary in summaries:
        portal_id = coerce_str(summary.get("id"))
        if portal_id is None:
            continue
        if (
            coerce_int(summary.get("authType")) == AUTH_TYPE_EXTERNAL_PORTAL
            or coerce_str(summary.get("name")) == spec.portal_name
            or ssid_id in _str_list(summary.get("ssidList"))
        ):
            details[portal_id] = await _portal_detail(
                client, omadac_id, site_id, portal_id
            )

    owned = [
        s
        for s in summaries
        if coerce_str(s.get("id")) is not None
        and _owns(s, details.get(str(s.get("id"))), spec)
    ]
    owned_ids = {str(s["id"]) for s in owned}
    foreign = [
        s
        for s in summaries
        if coerce_str(s.get("id")) is not None
        and str(s["id"]) not in owned_ids
        and ssid_id in _str_list(s.get("ssidList"))
    ]

    if foreign and not spec.take_over_ssid_portal:
        first = foreign[0]
        others = len(foreign) - 1
        return PortalSetupReport(
            dry_run=spec.dry_run,
            guest_ssid_id=ssid_id,
            block=PortalSetupBlock(
                kind="ssid_portal_conflict",
                message=(
                    f"The guest SSID '{ssid_label}' is already bound to the "
                    f"portal '{_safe_name(first.get('name'))}'"
                    + (f" (and {others} other portal(s))" if others else "")
                    + ", which this integration did not create. Nothing was "
                    "changed. Unbind the SSID from that portal on the "
                    "controller, or run again with take-over, which removes "
                    "only this SSID from that portal and changes nothing else "
                    "on it."
                ),
                portal_id=coerce_str(first.get("id")),
                portal_name=_safe_name(first.get("name")),
                match_count=len(foreign),
            ),
        )

    access_control_envelope = await client.request(
        "GET", ACCESS_CONTROL_PATH.format(**paths)
    )
    access_control = (
        access_control_envelope.result
        if isinstance(access_control_envelope.result, dict)
        else {}
    )

    state: dict[str, Any] = {
        "operator_credentials_set": False,
        "portal_id": (str(owned[0]["id"]) if len(owned) == 1 else None),
    }
    actions: list[_Action] = []

    # -- 0. take-over: release our SSID from foreign portals -----------------
    for summary in foreign:
        portal_id = str(summary["id"])
        portal_name = _safe_name(summary.get("name"))
        body, filled = released_portal_body(details.get(portal_id, {}), ssid_id)

        async def _release(portal_id: str = portal_id, body: dict = body) -> None:
            await client.request(
                "PATCH",
                PORTAL_PATH.format(portal_id=portal_id, **paths),
                json=body,
            )

        actions.append(
            _Action(
                step=STEP_SSID_TAKEOVER,
                outcome=PortalSetupOutcome.UPDATED,
                plan_message=(
                    f"Would remove SSID '{ssid_label}' from portal "
                    f"'{portal_name}'. Nothing else on that portal changes."
                ),
                done_message=(
                    f"Removed SSID '{ssid_label}' from portal '{portal_name}'. "
                    "Nothing else on that portal was changed."
                ),
                failure_prefix=(
                    f"Could not remove SSID '{ssid_label}' from portal "
                    f"'{portal_name}'."
                ),
                write=_release,
                details={
                    "portal_id": portal_id,
                    "portal_name": portal_name,
                    **({"required_fields_defaulted": filled} if filled else {}),
                },
            )
        )

    # -- 1. our portal -------------------------------------------------------
    if len(owned) > 1:
        names = ", ".join(f"'{_safe_name(s.get('name'))}'" for s in owned)
        actions.append(
            _Action(
                step=STEP_PORTAL,
                outcome=PortalSetupOutcome.FAILED,
                plan_message=(
                    f"More than one portal on this site belongs to this "
                    f"integration ({names}). Delete the extra one on the "
                    "controller, then run again. No portal was changed."
                ),
                details={"portal_ids": sorted(owned_ids)},
            )
        )
    elif not owned:
        body = new_portal_body(spec, ssid_id)

        async def _create_portal() -> _WriteResult:
            await client.request(
                "POST",
                ADD_PORTAL_PATH.format(**paths),
                json=body,
                retry_on_transport_error=False,
            )
            # ``addPortal`` answers without a result, so the id is read back.
            # Best effort: the portal exists whether or not this finds it.
            try:
                for row in await _list_portals(client, omadac_id, site_id):
                    if coerce_str(row.get("name")) == spec.portal_name:
                        state["portal_id"] = coerce_str(row.get("id"))
                        break
            except OmadaError:
                pass
            return _WriteResult(details={"portal_id": state["portal_id"]})

        actions.append(
            _Action(
                step=STEP_PORTAL,
                outcome=PortalSetupOutcome.CREATED,
                plan_message=(
                    f"Would create portal '{spec.portal_name}' (External "
                    f"Portal Server, {spec.portal_url_scheme}://"
                    f"{spec.portal_url}) bound to SSID '{ssid_label}'."
                ),
                done_message=(
                    f"Created portal '{spec.portal_name}' (External Portal "
                    f"Server) bound to SSID '{ssid_label}'."
                ),
                failure_prefix=f"Could not create portal '{spec.portal_name}'.",
                write=_create_portal,
                details={"portal_name": spec.portal_name, "ssid_id": ssid_id},
                depends_on=STEP_SSID_TAKEOVER if foreign else None,
            )
        )
    else:
        ours = owned[0]
        portal_id = str(ours["id"])
        detail = details.get(portal_id, {})
        drift = portal_drift(detail, spec, ssid_id)
        if not drift:
            actions.append(
                _Action(
                    step=STEP_PORTAL,
                    outcome=PortalSetupOutcome.UNCHANGED,
                    plan_message=(
                        f"Portal '{spec.portal_name}' already points at this "
                        f"venue's sign-in page and is bound to SSID "
                        f"'{ssid_label}'."
                    ),
                    details={"portal_id": portal_id},
                )
            )
        else:
            body = updated_portal_body(detail, spec, ssid_id)

            async def _update_portal(body: dict = body) -> None:
                await client.request(
                    "PATCH",
                    PORTAL_PATH.format(portal_id=portal_id, **paths),
                    json=body,
                )

            fields = ", ".join(drift)
            actions.append(
                _Action(
                    step=STEP_PORTAL,
                    outcome=PortalSetupOutcome.UPDATED,
                    plan_message=(
                        f"Would update portal '{spec.portal_name}': {fields}."
                    ),
                    done_message=(f"Updated portal '{spec.portal_name}': {fields}."),
                    failure_prefix=(f"Could not update portal '{spec.portal_name}'."),
                    write=_update_portal,
                    details={"portal_id": portal_id, "drift": drift},
                    depends_on=STEP_SSID_TAKEOVER if foreign else None,
                )
            )

    # -- 2. Pre-Authentication Access (merge-only) --------------------------
    host = spec.pre_auth_host
    merged, entry_added, was_enabled, existing = merged_access_control(
        access_control, host
    )
    if merged is None:
        actions.append(
            _Action(
                step=STEP_PRE_AUTH_ACCESS,
                outcome=PortalSetupOutcome.UNCHANGED,
                plan_message=(
                    f"Pre-Authentication Access already allows {host}. "
                    f"The {existing} entries on this site were left as they are."
                ),
                details={"host": host, "entries_preserved": existing},
            )
        )
    else:
        activation_note = (
            f" It was switched off; switching it on also activates the "
            f"{existing} entries already in the list."
            if not was_enabled and existing
            else ""
        )
        if entry_added:
            plan = f"Would add a URL entry for {host} to Pre-Authentication Access"
            done = f"Added a URL entry for {host} to Pre-Authentication Access"
        else:
            plan = (
                f"Would switch on Pre-Authentication Access (its {host} entry exists)"
            )
            done = f"Switched on Pre-Authentication Access (its {host} entry exists)"
        keep = f", keeping all {existing} existing entries." if existing else "."

        async def _merge(body: dict = merged) -> None:
            await client.request(
                "PATCH", ACCESS_CONTROL_PATH.format(**paths), json=body
            )

        actions.append(
            _Action(
                step=STEP_PRE_AUTH_ACCESS,
                outcome=(
                    PortalSetupOutcome.CREATED
                    if entry_added
                    else PortalSetupOutcome.UPDATED
                ),
                plan_message=plan + keep + activation_note,
                done_message=done + keep + activation_note,
                failure_prefix="Could not update Pre-Authentication Access.",
                write=_merge,
                details={
                    "host": host,
                    "entries_preserved": existing,
                    "was_enabled": was_enabled,
                },
            )
        )

    # -- 3. hotspot operator ------------------------------------------------
    actions.append(
        await _plan_operator(
            client,
            spec,
            paths,
            stored_operator=stored_operator,
            verify_operator_login=verify_operator_login,
            state=state,
        )
    )

    # -- apply ---------------------------------------------------------------
    steps = await _apply(actions, dry_run=spec.dry_run)
    return PortalSetupReport(
        dry_run=spec.dry_run,
        steps=tuple(steps),
        guest_ssid_id=ssid_id,
        portal_id=state["portal_id"],
        operator_credentials_set=bool(state["operator_credentials_set"]),
    )


async def _plan_operator(
    client: OmadaHttpClient,
    spec: PortalSetupSpec,
    paths: dict[str, str],
    *,
    stored_operator: tuple[str, str] | None,
    verify_operator_login: VerifyLogin,
    state: dict[str, Any],
) -> _Action:
    if stored_operator is not None:
        username, password = stored_operator
        shown = _safe_name(username)
        try:
            await verify_operator_login(username, password)
        except OmadaAuthError as exc:
            return _Action(
                step=STEP_HOTSPOT_OPERATOR,
                outcome=PortalSetupOutcome.FAILED,
                plan_message=(
                    f"The controller rejected the stored hotspot operator "
                    f"account '{shown}'. It was not changed: this platform "
                    "does not reset an account the venue may own. Check its "
                    "name and password in the controller's Hotspot Manager > "
                    "Operators and save them with Replace credentials -- or "
                    "save only the Open API app's credentials and run this "
                    "again to have a dedicated operator account created."
                ),
                provider_code=exc.provider_code,
            )
        return _Action(
            step=STEP_HOTSPOT_OPERATOR,
            outcome=PortalSetupOutcome.UNCHANGED,
            plan_message=(f"The stored hotspot operator account '{shown}' signs in."),
        )

    if not spec.create_operator_if_missing:
        return _Action(
            step=STEP_HOTSPOT_OPERATOR,
            outcome=PortalSetupOutcome.SKIPPED,
            plan_message="No hotspot operator account was requested.",
        )

    name = spec.operator_name
    rows = await client.get_all_pages(OPERATORS_PATH.format(**paths))
    match = next((r for r in rows if coerce_str(r.get("name")) == name), None)

    async def _verify_new(password: str) -> _WriteResult | None:
        try:
            await verify_operator_login(name, password)
        except OmadaAuthError as exc:
            return _WriteResult(
                outcome=PortalSetupOutcome.FAILED,
                message=(
                    f"Set up operator account '{name}', but the controller "
                    "then refused to sign it in. Its password is saved; run "
                    "this again, and if it still fails check the account in "
                    "Hotspot Manager > Operators."
                ),
                details={"provider_code": exc.provider_code},
            )
        return None

    if match is None:

        async def _create_operator() -> _WriteResult | None:
            password = spec.new_operator_password
            if not password:
                raise OmadaError("No password was supplied for the new operator.")
            await client.request(
                "POST",
                OPERATORS_PATH.format(**paths),
                json={
                    "name": name,
                    "password": password,
                    "note": spec.operator_note,
                    "operatorRoleType": OPERATOR_ROLE_ADMINISTRATOR,
                    "selectedSites": [spec.site_id],
                },
                retry_on_transport_error=False,
            )
            state["operator_credentials_set"] = True
            return await _verify_new(password)

        return _Action(
            step=STEP_HOTSPOT_OPERATOR,
            outcome=PortalSetupOutcome.CREATED,
            plan_message=(
                f"Would create hotspot operator account '{name}' for guest "
                "sign-in, with a generated password stored encrypted."
            ),
            done_message=(
                f"Created hotspot operator account '{name}' for guest "
                "sign-in; its generated password is stored encrypted."
            ),
            failure_prefix=f"Could not create hotspot operator account '{name}'.",
            write=_create_operator,
            details={"operator_name": name},
        )

    operator_id = coerce_str(match.get("id"))
    note = coerce_str(match.get("note")) or ""
    if spec.operator_marker not in note or operator_id is None:
        return _Action(
            step=STEP_HOTSPOT_OPERATOR,
            outcome=PortalSetupOutcome.FAILED,
            plan_message=(
                f"An operator account named '{name}' already exists on this "
                "site and was not created by this integration, so it was "
                "left alone. Rename or delete it on the controller, or save "
                "its credentials with Replace credentials, then run again."
            ),
            details={"operator_name": name},
        )

    selected = _str_list(match.get("selectedSites"))
    if spec.site_id not in selected:
        selected.append(spec.site_id)
    role = coerce_int(match.get("operatorRoleType"))

    async def _reset_operator() -> _WriteResult | None:
        password = spec.new_operator_password
        if not password:
            raise OmadaError("No password was supplied for the operator.")
        await client.request(
            "PATCH",
            OPERATOR_PATH.format(operator_id=operator_id, **paths),
            json={
                "name": name,
                "password": password,
                "note": note,
                "operatorRoleType": (
                    OPERATOR_ROLE_ADMINISTRATOR if role is None else role
                ),
                "selectedSites": selected,
            },
        )
        state["operator_credentials_set"] = True
        return await _verify_new(password)

    return _Action(
        step=STEP_HOTSPOT_OPERATOR,
        outcome=PortalSetupOutcome.UPDATED,
        plan_message=(
            f"Would reset the password of this integration's own operator "
            f"account '{name}', left by an earlier run whose credentials were "
            "never saved."
        ),
        done_message=(
            f"Reset the password of this integration's own operator account "
            f"'{name}' (left by an earlier run whose credentials were never "
            "saved); it is now stored encrypted."
        ),
        failure_prefix=f"Could not reset operator account '{name}'.",
        write=_reset_operator,
        details={"operator_name": name},
    )


async def _apply(actions: list[_Action], *, dry_run: bool) -> list[PortalSetupStep]:
    steps: list[PortalSetupStep] = []
    failed_steps: set[str] = set()
    lost_contact = False
    for action in actions:
        if action.write is None or dry_run:
            if action.outcome is PortalSetupOutcome.FAILED:
                failed_steps.add(action.step)
            steps.append(
                PortalSetupStep(
                    step=action.step,
                    outcome=action.outcome,
                    message=action.plan_message,
                    provider_code=action.provider_code,
                    details=action.details,
                )
            )
            continue
        if lost_contact or (action.depends_on and action.depends_on in failed_steps):
            reason = (
                "an earlier step lost contact with the controller."
                if lost_contact
                else "the guest SSID could not be released from the other portal."
            )
            failed_steps.add(action.step)
            steps.append(
                PortalSetupStep(
                    step=action.step,
                    outcome=PortalSetupOutcome.SKIPPED,
                    message=f"Not attempted: {reason}",
                    details=action.details,
                )
            )
            continue
        try:
            result = await action.write()
        except OmadaError as exc:
            if isinstance(exc, _LOST_CONTACT):
                lost_contact = True
            failed_steps.add(action.step)
            steps.append(
                PortalSetupStep(
                    step=action.step,
                    outcome=PortalSetupOutcome.FAILED,
                    message=f"{action.failure_prefix} {exc}".strip(),
                    provider_code=exc.provider_code,
                    details=action.details,
                )
            )
            continue
        result = result or _WriteResult()
        outcome = result.outcome or action.outcome
        if outcome is PortalSetupOutcome.FAILED:
            failed_steps.add(action.step)
        provider_code = result.details.pop("provider_code", None)
        steps.append(
            PortalSetupStep(
                step=action.step,
                outcome=outcome,
                message=result.message or action.done_message,
                provider_code=provider_code if isinstance(provider_code, int) else None,
                details={**action.details, **result.details},
            )
        )
    return steps


__all__ = [
    "ACCESS_CONTROL_PATH",
    "ADD_PORTAL_PATH",
    "AUTH_TYPE_EXTERNAL_PORTAL",
    "HOST_TYPE_URL",
    "OPERATORS_PATH",
    "OPERATOR_PATH",
    "OPERATOR_ROLE_ADMINISTRATOR",
    "PORTALS_PATH",
    "PORTAL_PATH",
    "PRE_AUTH_POLICY_TYPE_URL",
    "STEP_HOTSPOT_OPERATOR",
    "STEP_PORTAL",
    "STEP_PRE_AUTH_ACCESS",
    "STEP_SSID_TAKEOVER",
    "auth_timeout_setting",
    "configure_external_portal",
    "host_of",
    "merged_access_control",
    "new_portal_body",
    "portal_drift",
    "portal_setting_from_detail",
    "released_portal_body",
    "resolve_ssid",
    "updated_portal_body",
]

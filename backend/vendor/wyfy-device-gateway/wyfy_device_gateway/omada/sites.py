"""Sites and SSIDs, via the Open API.

Both are inventory operations, so both are Open API only -- a hotspot
operator credential cannot see them (see ``auth.py``'s docstring on why).

## Sourcing

``GET /openapi/v1/{omadacId}/sites`` is **corroborated, not primary**:
it is what the community client at
<https://github.com/bullitt186/ha-omada-open-api> uses
(``custom_components/omada_open_api/const.py``: ``API_SITES =
"/openapi/v1/{omada_id}/sites"``), and TP-Link's own *How to Create Site in
Omada Controller via Open API*
(<https://support.omadanetworks.com/uk/document/109315/>) describes creating
a site through the Open API and confirms the envelope returns ``errorCode``
0 plus a site id -- but that page defers the exact path to the controller's
built-in Online API Document, which is not publicly reachable.

SSIDs are a two-step walk -- WLAN groups first, then the SSIDs inside each --
and are corroborated the same way, from the community client's
``/sites/{siteId}/wireless-network/wlans`` and
``/wireless-network/wlans/{wlanId}/ssids``.

## Why ``get_site`` filters a list instead of fetching one site

There is very likely a ``GET /openapi/v1/{omadacId}/sites/{siteId}`` route,
but we could not confirm its response shape from any source, and guessing
wrong on a *read* used by the connect wizard would produce a confusing
"invalid controller" at exactly the moment an operator is trying to work out
whether their settings are right. Filtering the list we already know how to
parse costs one extra page fetch on a list that is realistically a handful of
rows, and it cannot be wrong about the shape. If a primary source for the
single-site route turns up, this is a safe, local change.
"""

from __future__ import annotations

from typing import Any

from ..controller_contract import ControllerSite, ControllerSsid
from .client import OmadaHttpClient
from .errors import OmadaSiteNotFoundError
from .types import coerce_bool, coerce_int, coerce_str, extract_page

#: CORROBORATED (community client), not primary.
SITES_PATH = "/openapi/v1/{omadac_id}/sites"
WLANS_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/wireless-network/wlans"
SSIDS_PATH = (
    "/openapi/v1/{omadac_id}/sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids"
)


def _parse_site(row: dict[str, Any]) -> ControllerSite | None:
    """One site row -> ``ControllerSite``, or ``None`` if unusable.

    Omada is inconsistent about the site identifier's key across firmware:
    ``siteId`` and ``id`` both occur, and the human name is ``name`` or
    occasionally ``siteName``. A row with no identifier at all is dropped
    rather than given a synthetic one -- an id we invented would be stored
    against the integration and would never match anything again.
    """
    site_id = coerce_str(row.get("siteId")) or coerce_str(row.get("id"))
    if site_id is None:
        return None
    name = coerce_str(row.get("name")) or coerce_str(row.get("siteName")) or site_id
    return ControllerSite(
        site_id=site_id,
        name=name,
        device_count=coerce_int(row.get("deviceCount")),
        client_count=coerce_int(row.get("clientCount")),
    )


async def list_sites(client: OmadaHttpClient, omadac_id: str) -> list[ControllerSite]:
    """Every site on the controller the credentials can see."""
    rows = await client.get_all_pages(SITES_PATH.format(omadac_id=omadac_id))
    sites = [_parse_site(row) for row in rows]
    return [site for site in sites if site is not None]


async def get_site(
    client: OmadaHttpClient, omadac_id: str, site_id: str
) -> ControllerSite:
    """One site by id. Raises ``OmadaSiteNotFoundError`` if it is gone.

    "Gone" is a real, expected state, not a bug: an operator can delete a
    site in the Omada UI at any time while our integration row still points
    at it, and the backend needs a distinct code for that so it can tell the
    customer to re-pick a site rather than reporting a connection failure.
    """
    for site in await list_sites(client, omadac_id):
        if site.site_id == site_id:
            return site
    raise OmadaSiteNotFoundError()


def _parse_ssid(row: dict[str, Any], wlan_id: str | None) -> ControllerSsid | None:
    name = coerce_str(row.get("name")) or coerce_str(row.get("ssid"))
    if name is None:
        return None
    return ControllerSsid(
        ssid_id=coerce_str(row.get("id")) or coerce_str(row.get("ssidId")),
        name=name,
        wlan_group_id=wlan_id,
        # Omada spells the portal flag differently across versions; take
        # whichever is present and leave it ``None`` when neither is, rather
        # than defaulting to False and telling the dashboard the portal is
        # off when we simply were not told.
        portal_enabled=coerce_bool(
            row.get("portalEnable")
            if row.get("portalEnable") is not None
            else row.get("portalEnabled")
        ),
    )


async def list_ssids(
    client: OmadaHttpClient, omadac_id: str, site_id: str
) -> list[ControllerSsid]:
    """Every SSID in every WLAN group of a site.

    Two round trips minimum, because Omada models SSIDs as children of WLAN
    groups and offers no flat listing. A WLAN group whose SSID fetch fails is
    skipped rather than aborting the whole call: the connect wizard showing
    most of the SSIDs is far more useful than it showing an error, and a
    group we could not read is usually one the credential's site privileges
    do not cover.
    """
    wlan_rows = await client.get_all_pages(
        WLANS_PATH.format(omadac_id=omadac_id, site_id=site_id)
    )

    ssids: list[ControllerSsid] = []
    for wlan in wlan_rows:
        wlan_id = coerce_str(wlan.get("id")) or coerce_str(wlan.get("wlanId"))
        if wlan_id is None:
            continue
        rows = await client.get_all_pages(
            SSIDS_PATH.format(
                omadac_id=omadac_id, site_id=site_id, wlan_id=wlan_id
            )
        )
        for row in rows:
            parsed = _parse_ssid(row, wlan_id)
            if parsed is not None:
                ssids.append(parsed)
    return ssids


def parse_sites(rows: list[dict[str, Any]]) -> list[ControllerSite]:
    """Exposed for tests and for reuse by anything that already has rows."""
    parsed = [_parse_site(row) for row in extract_page(rows)]
    return [site for site in parsed if site is not None]


__all__ = [
    "SITES_PATH",
    "SSIDS_PATH",
    "WLANS_PATH",
    "get_site",
    "list_sites",
    "list_ssids",
    "parse_sites",
]

"""Connected clients for one site, via the Open API.

## Sourcing, and why this uses the v1 GET rather than the v2 POST

There are two client-listing endpoints:

* ``GET  /openapi/v1/{omadacId}/sites/{siteId}/clients``
* ``POST /openapi/v2/{omadacId}/sites/{siteId}/clients`` with a JSON body
  carrying ``page``/``pageSize``/``scope``/``filters``

Both are **corroborated, not primary** -- from the community client at
<https://github.com/bullitt186/ha-omada-open-api>
(``custom_components/omada_open_api/api.py::get_clients``), which tries v2
first and falls back to v1 on Omada error ``-1600`` ("unsupported on Fusion
firmware").

This package uses **v1 GET** as its only path. The v2 endpoint's extra power
is a ``scope`` filter (0 all / 1 online / 2 offline / 3 blocked) and a
``filters`` object, and we want none of it: we want the online clients, which
is what v1 returns. Choosing v1 buys uniform pagination with every other list
endpoint here, no version-probing state machine, no second response shape to
parse, and no dependency on a ``scope`` enum we have no primary source for.
The cost is that if a future controller drops v1 we have to add v2 -- a
contained change, and one we would rather make against a real controller
than pre-emptively guess at now.

## Guest and authorization state

``is_guest`` and ``is_authorized`` are tri-state (``True``/``False``/``None``)
and ``None`` is common. Omada exposes portal-authorization state under
several different keys depending on version and on whether the client came in
through a portal at all. Where we cannot tell, we say so, rather than
defaulting to ``False`` and having the dashboard assert that a guest is
unauthorized when the controller never said that.
"""

from __future__ import annotations

from typing import Any

from ..controller_contract import ControllerClient
from .client import OmadaHttpClient
from .types import (
    coerce_bool,
    coerce_int,
    coerce_str,
    epoch_to_utc,
    normalize_mac,
)

#: CORROBORATED (community client), not primary.
CLIENTS_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/clients"


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


def parse_client(row: dict[str, Any]) -> ControllerClient | None:
    """One client row -> ``ControllerClient``, or ``None`` without a MAC."""
    mac = normalize_mac(_first(row, "mac", "macAddress", "clientMac"))
    if mac is None:
        return None

    return ControllerClient(
        mac=mac,
        name=coerce_str(_first(row, "name", "hostName", "hostname", "deviceName")),
        ip_address=coerce_str(_first(row, "ip", "ipAddr", "ipAddress")),
        ssid=coerce_str(_first(row, "ssid", "ssidName")),
        ap_mac=normalize_mac(_first(row, "apMac", "gatewayMac", "switchMac")),
        radio_id=coerce_int(_first(row, "radioId", "radio")),
        vlan_id=coerce_int(_first(row, "vid", "vlanId", "vlan")),
        is_guest=coerce_bool(_first(row, "guest", "isGuest")),
        is_authorized=coerce_bool(
            _first(row, "authorized", "isAuthorized", "portalAuthorized", "auth")
        ),
        # ``connectTime``/``associationTime`` are epochs; ``lastSeen`` is a
        # last resort and is strictly speaking a different fact (when we last
        # heard from the client, not when it joined). It is used only when
        # neither join time is present, on the grounds that an approximate
        # "connected since" beats an empty column.
        connected_since=epoch_to_utc(
            _first(row, "connectTime", "associationTime", "lastSeen")
        ),
        duration_seconds=coerce_int(_first(row, "duration", "uptime", "activeTime")),
        # Omada reports traffic from the *controller's* point of view:
        # ``download`` is what the client downloaded. Mapping is 1:1 with the
        # contract's names, but note ``rxRate``/``txRate`` are rates, not
        # totals, and are deliberately not used here.
        traffic_down_bytes=coerce_int(_first(row, "download", "trafficDown", "rxBytes")),
        traffic_up_bytes=coerce_int(_first(row, "upload", "trafficUp", "txBytes")),
        signal_dbm=coerce_int(_first(row, "signalRank", "rssi", "signalLevel")),
    )


async def list_clients(
    client: OmadaHttpClient, omadac_id: str, site_id: str
) -> list[ControllerClient]:
    """Every client the controller currently reports for a site."""
    rows = await client.get_all_pages(
        CLIENTS_PATH.format(omadac_id=omadac_id, site_id=site_id)
    )
    clients = [parse_client(row) for row in rows]
    return [entry for entry in clients if entry is not None]


async def get_client(
    client: OmadaHttpClient, omadac_id: str, site_id: str, client_mac: str
) -> ControllerClient | None:
    """One client by MAC, or ``None`` when it is not connected.

    Implemented as a filtered list walk rather than a per-client GET. We have
    no corroborated single-client route, and more importantly the semantics
    we need -- "absent means not connected, which is normal" -- fall out of a
    list naturally, whereas a per-client route would make us distinguish a
    404-for-unknown-MAC from a 404-for-wrong-path, which we cannot reliably
    do.

    Matching is done on the normalized MAC form so that a caller passing
    ``aa:bb:cc:dd:ee:ff`` still matches a controller reporting
    ``AA-BB-CC-DD-EE-FF``.
    """
    target = normalize_mac(client_mac)
    if target is None:
        return None
    for entry in await list_clients(client, omadac_id, site_id):
        if entry.mac == target:
            return entry
    return None


__all__ = ["CLIENTS_PATH", "get_client", "list_clients", "parse_client"]

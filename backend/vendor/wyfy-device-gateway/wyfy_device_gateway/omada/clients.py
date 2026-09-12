"""Connected clients for one site, via the Open API.

## Sourcing, and why this uses the v1 GET rather than the v2 POST

There are two client-listing endpoints:

* ``GET  /openapi/v1/{omadacId}/sites/{siteId}/clients``
* ``POST /openapi/v2/{omadacId}/sites/{siteId}/clients`` with a JSON body
  carrying ``page``/``pageSize``/``scope``/``filters``

Both are **VERIFIED against a primary TP-Link source** as of 2026-09-10:
they appear in TP-Link's own OpenAPI 3.0.1 specification at
<https://use1-omada-northbound.tplinkcloud.com/v3/api-docs> as
``GET .../clients`` ("Get client list", ``page``/``pageSize`` required) and
``POST /openapi/v2/...`` respectively. They were previously corroborated only
by the community client at <https://github.com/bullitt186/ha-omada-open-api>
(``custom_components/omada_open_api/api.py::get_clients``), which tries v2
first and falls back to v1 on Omada error ``-1600``.

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

``is_guest`` and ``is_authorized`` are tri-state (``True``/``False``/
``None``) and ``None`` is a real answer, not a failure. ``is_guest`` comes
from ``guest``, documented as "(Wireless) Whether it is Guest", so it is
absent for wired clients. ``is_authorized`` comes from ``authStatus`` -- see
``_parse_auth_status``, and note that the four boolean key names this module
used to look for do not exist in TP-Link's schema at all.

Where we cannot tell, we say so, rather than defaulting to ``False`` and
having the dashboard assert that a guest is unauthorized when the controller
never said that.

## Fields verified against the spec, and one that is approximate

``mac``, ``name``/``hostName``, ``ip``, ``ssid``, ``apMac``, ``radioId``,
``vid``, ``guest``, ``trafficDown``/``trafficUp`` (both "Byte"), ``uptime``
("Up time (unit: s)") and ``rssi`` ("Signal strength, unit: dBm") are all
present in ``OpenApi Client Info`` exactly as read here.

``connected_since`` is the approximate one. The spec has no join timestamp:
no ``connectTime``, no ``associationTime``. It has ``lastSeen``, "Last found
time, timestamp (ms)", which is when the controller last heard from the
client -- a different fact. It is used because an approximate "connected
since" beats an empty column, but a caller wanting the real join time should
derive it from ``duration_seconds`` (``uptime``, which the spec does define
in seconds) instead.
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

#: VERIFIED (TP-Link OpenAPI spec, "Get client list").
CLIENTS_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/clients"


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


#: VERIFIED (TP-Link's OpenAPI spec, ``OpenApi Client Info.authStatus``):
#: "0: CONNECTED // Access without any authentication method; 1: PENDING //
#: Access to Portal, but authentication failed; 2: AUTHORIZED // Pass through
#: portal, pass other authentication without portal; 3: AUTH-FREE // No
#: portal authentication required."
#:
#: Only 2 is an authorized guest. 3 (auth-free) is mapped to ``None`` rather
#: than ``True`` or ``False`` on purpose: the client has access, but not
#: because anything authorized it, so neither answer is honest and the
#: contract's tri-state exists precisely for this.
_AUTH_STATUS_AUTHORIZED = 2
_AUTH_STATUS_PENDING = 1
_AUTH_STATUS_CONNECTED_NO_AUTH = 0


def _parse_auth_status(row: dict[str, Any]) -> bool | None:
    """Portal-authorization state, from ``authStatus`` where it exists.

    The previous implementation looked for ``authorized`` / ``isAuthorized``
    / ``portalAuthorized`` / ``auth``. None of those four keys exists in
    TP-Link's published client schema, so this field was silently ``None``
    for every client on every controller. The boolean fallbacks are kept
    after ``authStatus`` only because they cost nothing and an older
    firmware's shape is not something this spec can rule out.
    """
    status = coerce_int(row.get("authStatus"))
    if status is not None:
        if status == _AUTH_STATUS_AUTHORIZED:
            return True
        if status in (_AUTH_STATUS_PENDING, _AUTH_STATUS_CONNECTED_NO_AUTH):
            return False
        return None
    return coerce_bool(
        _first(row, "authorized", "isAuthorized", "portalAuthorized", "auth")
    )


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
        is_authorized=_parse_auth_status(row),
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
        traffic_down_bytes=coerce_int(_first(row, "trafficDown", "download", "rxBytes")),
        traffic_up_bytes=coerce_int(_first(row, "trafficUp", "upload", "txBytes")),
        # VERIFIED (TP-Link's OpenAPI spec, ``OpenApi Client Info``): ``rssi``
        # is "Signal strength, unit: dBm" and is the ONLY field here in dBm.
        # ``signalRank`` is "Signal strength level ... within the range of
        # 0-5" and ``signalLevel`` is "Signal strength percentage ... 0-100".
        # This list previously tried ``signalRank`` first, which would have
        # reported a 0-5 bar count as a dBm figure -- so a guest sitting at
        # -45 dBm right under the AP would have displayed as "5 dBm" and one
        # at the edge of coverage as "1 dBm". Both are nonsense as dBm, and
        # neither looks obviously wrong enough to get noticed. dBm-only now:
        # if the controller does not give us dBm we report nothing, because
        # the contract field is named ``signal_dbm`` and a bar count is not
        # one.
        signal_dbm=coerce_int(row.get("rssi")),
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

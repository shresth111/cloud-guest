"""Ending one guest's portal authorization early.

## Why this module exists at all

``adapter.deauthorize_guest`` used to raise ``OmadaUnsupportedApiError``
unconditionally, on the stated grounds that TP-Link publishes no way to
revoke an external-portal authorization. That grounds was a claim about
TP-Link's *external-portal document family* (13023 / 13080 / 132060), and
about those three documents it is accurate: they describe exactly two calls,
operator login and client authorization, and none of them mentions
revocation.

It was not accurate about the controller. The Hotspot Manager's **Authorized
Clients** table has an unauthorize action; it is served by the same
``/{omadacId}/api/v2/hotspot/...`` tree the operator login already opens, and
it is authenticated by the very session ``extPortal/auth`` already
establishes. No Open API credentials, no new configuration, and no firmware
floor above the v5.0.15 this package already requires.

## The two endpoints -- OBSERVED on hardware, not documented

Neither path appears in any TP-Link document we can reach. Both were
captured from the controller's own web UI and then re-issued by hand against
a live controller (Omada Software Controller **5.15.24.19**, omadacId
``15ab...ec59``, site ``6aa3...35a1``) holding nothing but a hotspot-operator
session::

    GET  /{omadacId}/api/v2/hotspot/sites/{siteId}/clients
    POST /{omadacId}/api/v2/hotspot/sites/{siteId}/cmd/clients/{id}/disconnect

Every claim in this module is tagged **OBSERVED** rather than VERIFIED, and
the distinction is deliberate: a documented endpoint is a promise about
future firmware, an observed one is a fact about one firmware. If TP-Link
moves these paths, ``_disconnect_one`` fails loudly with ``-1600 "Unsupported
request path."`` rather than quietly reporting a revocation it did not
perform. That failure mode is the entire reason the previous implementation
refused outright, and it is preserved. Those tags stay OBSERVED: the
research below corroborates the *operation*, never these two paths.

## What the operation is, in TP-Link's own words (added 2026-09-12)

The two legacy paths remain undocumented -- no TP-Link page, no public code,
nothing. But the operation they perform is documented twice over, and both
descriptions match what was measured here field for field, which is a good
deal more reassurance than "we saw it once".

TP-Link's Open API exposes the same three actions on the same table, on the
same controller, keyed the same way (spec:
<https://use1-omada-northbound.tplinkcloud.com/v3/api-docs>):

    GET  /openapi/v1/{omadacId}/sites/{siteId}/hotspot/authed-records
    POST /openapi/v1/{omadacId}/sites/{siteId}/hotspot/authed-records/{id}/disconnect
    POST /openapi/v1/{omadacId}/sites/{siteId}/hotspot/clients/{clientMac}/unauth

The list returns ``AuthClientOpenApiVO``, whose documented fields are exactly
the ones the legacy rows carry and exactly the ones matched on below:
``id`` ("AuthRecord ID"), ``mac``, ``valid`` ("Is the client valid"),
``duration`` ("Total Duration (s)"), ``start``, ``end``. So the record-id
keying is not an accident of the web UI -- it is how Omada models this table,
and ``.../authed-records/{id}/disconnect`` is the documented twin of the
observed ``.../cmd/clients/{id}/disconnect``.

TP-Link's user guide independently confirms the two behaviours this module's
matching rule is built on: the Authorized Clients page shows "the clients
authorized by portal system, **including the expired clients and the clients
within the valid period**" -- a history, not a set of live grants -- and its
action column offers extend, disconnect and delete.

One difference is worth keeping in view, because it is the trap called out
under "Paging" below: the documented Open API list pages with
``page``/``pageSize`` ("within the range of 1-1000"), while the legacy
hotspot list measured here pages with ``currentPage``/``currentPageSize``.
Two conventions, two APIs. Same table.

None of this makes the legacy paths safe to assume on firmware other than the
one they were measured on, and nothing here has been run against an OC200,
an OC300 or a cloud-based controller. See
``backend/docs/network_integration/OMADA_HARDWARE_VERIFICATION.md`` test 5.

## The path takes a record id, not a MAC

This is why the module is more than one function. The disconnect path is
keyed on the **authorized-client record id** (``result.data[].id``, a 24-hex
controller object id), not on the client MAC -- and a MAC is all the backend
ever holds. So a caller must list first and match.

## A disconnected row is not deleted, which changes the matching rule

Measured on the live controller, same row before and after a disconnect::

    before  {"id": "6aa3c4b9...", "mac": "AA-BB-CC-DD-EE-77",
             "valid": true,  "duration": 0,   "end": 1789121225605}
    after   {"id": "6aa3c4b9...", "mac": "AA-BB-CC-DD-EE-77",
             "valid": false, "duration": 41,  "end": <moment of disconnect>}

The row survives. ``valid`` flips to ``false``, ``end`` is rewritten to the
instant of the disconnect and ``duration`` is filled in. This table is a
**history**, not a set of live grants, and any MAC that has been on the
network before matches rows that are already over.

Matching on MAC alone would therefore fail *quietly*: it would pick some
arbitrary historical row, disconnect it "successfully" -- the controller
answers ``errorCode: 0`` when asked to re-disconnect an already-invalid row,
also measured -- and report success while the guest stayed online under a
different, still-valid row. So every match here is **MAC and ``valid`` is
true**.

For the same reason this ends **every** valid row for the MAC rather than
the newest. One device can hold more than one live grant -- re-authorizing
through the portal while an earlier one is still running is the ordinary way
that happens -- and ending the newest while an older one stays valid is
exactly the false success this module exists to prevent.

## "No row" is success, not an error

A MAC with no valid row is already not authorized: that is the end state the
caller asked for, so it returns ``True``. Raising instead would make
"disconnect a guest who already timed out" an error in a dashboard and would
make the operation non-idempotent for no gain.

The same reasoning covers the race the other way. If the row is ended by
someone else between our list and our POST, the controller answers
``errorCode -1001 "Auth record does not exist."`` -- measured, for both a
well-formed-but-absent id and a malformed one. That is success for that row.

## Paging, and the silent-failure trap in it

Open API list endpoints page with ``page`` / ``pageSize``, which is what
``OmadaHttpClient.get_all_pages`` sends. **This legacy hotspot endpoint does
not.** It pages with ``currentPage`` / ``currentPageSize`` and -- measured --
it *ignores* ``page`` / ``pageSize`` in silence, answering with page 1 at its
default size of 10 and ``errorCode: 0``::

    ?page=1&pageSize=1          -> currentSize 10, 10 rows   (ignored)
    ?currentPage=1&currentPageSize=1 -> currentSize 1, 1 row  (honoured)

Reusing ``get_all_pages`` here would appear to work, scan the first ten rows
only, and miss the guest on any site busier than a demo. Hence the local
paging loop.

``searchKey`` narrows the table server-side. Measured: it substring-matches
the MAC in **hyphen-separated** form (and the RADIUS username), case
insensitively; colon-separated and bare-hex MACs match nothing. It is sent
purely as an optimization and correctness never rests on it -- every row that
comes back is still matched exactly on a normalized MAC, and the walk still
pages. A firmware that ignored ``searchKey`` would degrade to a bounded full
scan, not to a wrong answer.
"""

from __future__ import annotations

import logging
from typing import Any

from .client import OmadaHttpClient
from .errors import OmadaError
from .types import (
    coerce_bool,
    coerce_str,
    extract_page,
    extract_total_rows,
    normalize_mac,
)

logger = logging.getLogger(__name__)

#: OBSERVED (controller 5.15.24.19): the Authorized Clients table.
AUTHORIZED_CLIENTS_PATH = "/{omadac_id}/api/v2/hotspot/sites/{site_id}/clients"
#: OBSERVED (controller 5.15.24.19): end one authorization by record id.
DISCONNECT_PATH = (
    "/{omadac_id}/api/v2/hotspot/sites/{site_id}/cmd/clients/{record_id}/disconnect"
)

#: OBSERVED: this endpoint's paging parameters. Not ``page``/``pageSize`` --
#: see the module docstring for why that distinction is load-bearing.
PAGE_PARAM = "currentPage"
PAGE_SIZE_PARAM = "currentPageSize"
#: OBSERVED: server-side narrowing. Substring match on the hyphenated MAC.
SEARCH_PARAM = "searchKey"

#: 100 rows a page, 20 pages. Deliberately tighter than ``client.MAX_PAGES``
#: (100): this walk runs inline on an operator's click rather than in a
#: background task, and 2,000 authorization records is already well past any
#: venue we expect. Reaching the cap is logged and reported as "not
#: authorized", so the cap is generous enough that hitting it means
#: something is wrong rather than merely busy.
PAGE_SIZE = 100
MAX_PAGES = 20

#: OBSERVED: the controller's answer to a disconnect naming a record id it
#: does not have -- ``{"errorCode": -1001, "msg": "Auth record does not
#: exist."}`` -- for both an absent well-formed id and a malformed one.
AUTH_RECORD_NOT_FOUND = -1001


def parse_authorized_client(row: dict[str, Any]) -> tuple[str, str, bool] | None:
    """``(record_id, normalized_mac, is_valid)`` for one Authorized Clients row.

    ``None`` for a row missing either an id or a MAC, since such a row is one
    we could neither match nor act on. Kept pure so the match rule can be
    tested with no HTTP in the way -- this is the decision that separates
    "ended the right guest's access" from "reported success against a row
    from last Tuesday".
    """
    record_id = coerce_str(row.get("id"))
    mac = normalize_mac(row.get("mac"))
    if not record_id or not mac:
        return None
    # An absent ``valid`` is read as valid. The field is on every row this
    # controller returns; if some firmware omitted it, refusing to disconnect
    # anything would be the worse of the two failures.
    is_valid = coerce_bool(row.get("valid"))
    return record_id, mac, True if is_valid is None else is_valid


async def find_valid_authorizations(
    client: OmadaHttpClient,
    omadac_id: str,
    site_id: str,
    client_mac: str,
) -> list[str]:
    """Record ids of every *currently valid* authorization held by one MAC.

    An empty list means the MAC holds no live authorization on this site,
    which callers read as "already not authorized" rather than as an error.
    """
    wanted = normalize_mac(client_mac)
    if not wanted:
        return []

    found: list[str] = []
    seen = 0
    path = AUTHORIZED_CLIENTS_PATH.format(omadac_id=omadac_id, site_id=site_id)
    for page in range(1, MAX_PAGES + 1):
        envelope = await client.request(
            "GET",
            path,
            params={
                PAGE_PARAM: page,
                PAGE_SIZE_PARAM: PAGE_SIZE,
                # Hyphen-upper is the form this endpoint matches on, and it
                # is exactly what ``normalize_mac`` produces.
                SEARCH_PARAM: wanted,
            },
        )
        batch = extract_page(envelope.result)
        seen += len(batch)
        for row in batch:
            parsed = parse_authorized_client(row)
            if parsed is None:
                continue
            record_id, mac, is_valid = parsed
            if mac == wanted and is_valid:
                found.append(record_id)
        if not batch or len(batch) < PAGE_SIZE:
            break
        total = extract_total_rows(envelope.result)
        if total is not None and seen >= total:
            break
    else:
        logger.warning(
            "omada_authorized_clients_page_cap",
            extra={"site_id": site_id, "max_pages": MAX_PAGES},
        )
    return found


async def _disconnect_one(
    client: OmadaHttpClient, omadac_id: str, site_id: str, record_id: str
) -> bool:
    """End one authorization by record id. ``True`` once it is ended.

    ``AUTH_RECORD_NOT_FOUND`` counts as ended: between our list and this POST
    the row may have expired, been ended by an operator in the controller's
    own UI, or been ended by a second click on our button. In all three the
    guest's access is over, which is what the caller asked for.

    Every other error propagates untouched -- including the ``-1600
    "Unsupported request path."`` that a firmware which moved these paths
    would return. Failing loudly there is the point.
    """
    try:
        await client.request(
            "POST",
            DISCONNECT_PATH.format(
                omadac_id=omadac_id, site_id=site_id, record_id=record_id
            ),
            json={},
        )
    except OmadaError as exc:
        if exc.provider_code == AUTH_RECORD_NOT_FOUND:
            logger.info(
                "omada_disconnect_record_already_gone", extra={"site_id": site_id}
            )
            return True
        raise
    return True


async def deauthorize_client(
    client: OmadaHttpClient,
    omadac_id: str,
    site_id: str,
    client_mac: str,
) -> bool:
    """End every valid portal authorization one MAC holds on one site.

    Returns ``True`` when the MAC is not authorized afterwards -- including
    the case where it never was. It never returns ``False``: the only
    non-success outcome is a raised, normalized ``OmadaError``, because "the
    controller was asked and declined" is not an outcome this endpoint
    produces. The ``bool`` is the contract's, kept so that a vendor which
    *can* decline has somewhere to say so.
    """
    record_ids = await find_valid_authorizations(client, omadac_id, site_id, client_mac)
    if not record_ids:
        logger.info(
            "omada_deauthorize_no_active_authorization", extra={"site_id": site_id}
        )
        return True
    for record_id in record_ids:
        await _disconnect_one(client, omadac_id, site_id, record_id)
    logger.info(
        "omada_deauthorized", extra={"site_id": site_id, "records": len(record_ids)}
    )
    return True


__all__ = [
    "AUTHORIZED_CLIENTS_PATH",
    "AUTH_RECORD_NOT_FOUND",
    "DISCONNECT_PATH",
    "MAX_PAGES",
    "PAGE_SIZE",
    "PAGE_PARAM",
    "PAGE_SIZE_PARAM",
    "SEARCH_PARAM",
    "deauthorize_client",
    "find_valid_authorizations",
    "parse_authorized_client",
]

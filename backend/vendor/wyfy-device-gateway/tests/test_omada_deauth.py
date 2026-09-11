"""Ending one guest's authorization -- the endpoint CR-001 said did not exist.

These tests pin the two things that make this operation either correct or
quietly wrong:

* **which row is ended.** The Authorized Clients table is a history, not a
  set of live grants, so a match on MAC alone finds rows that are already
  over. Disconnecting one of those succeeds at the controller and leaves
  the guest online -- a success message over an unchanged network.
* **which paging parameters are sent.** The legacy hotspot endpoint ignores
  ``page``/``pageSize`` silently and answers page 1 at size 10. Getting
  that wrong looks like working code right up until a venue has more than
  ten authorization records.

Both were measured against a real controller (5.15.24.19); these tests are
where that measurement is written down in a form that fails if someone
changes it back.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from wyfy_device_gateway.controller_contract import ControllerAuthMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.deauth import (
    PAGE_SIZE,
    parse_authorized_client,
)
from wyfy_device_gateway.omada.errors import OmadaError, OmadaUnsupportedApiError

from omada_support import (
    OMADAC_ID,
    FakeOmadaController,
    envelope,
    make_creds,
    no_sleep,
)

SITE_ID = "6aa3913c3ee1605f71ac35a1"
LIST_PATH = f"/{OMADAC_ID}/api/v2/hotspot/sites/{SITE_ID}/clients"
GUEST_MAC = "AA-BB-CC-DD-EE-77"


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(transport=controller.transport(), sleep=no_sleep)


def row(
    record_id: str, mac: str = GUEST_MAC, *, valid: bool = True, **extra: Any
) -> dict[str, Any]:
    """One Authorized Clients row, shaped exactly as the real one.

    Field names and types copied from a live 5.15.24.19 response rather
    than invented, so a test passing here means the parser handles the
    controller's actual output.
    """
    base = {
        "id": record_id,
        "mac": mac,
        "wireless": True,
        "ssid": "WyfyGuest",
        "authType": 4,
        "download": 0,
        "upload": 0,
        "duration": 0,
        "start": 1789117625605,
        "end": 1789121225605,
        "valid": valid,
        "permanent": False,
    }
    base.update(extra)
    return base


class HotspotClientsTable:
    """The controller's Authorized Clients table, paging as the real one does.

    Honours ``currentPage``/``currentPageSize`` and **ignores**
    ``page``/``pageSize`` -- the measured behaviour, reproduced here so a
    client that sends the Open API spelling reads ten rows and believes it
    read the table.
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.list_queries: list[httpx.QueryParams] = []
        self.disconnected: list[str] = []
        #: Override the answer to a disconnect, for the error-path tests.
        self.disconnect_error: tuple[int, str] | None = None
        #: Set ``False`` to model a firmware that ignores ``searchKey``.
        #: Correctness must survive that -- it degrades the walk to a
        #: bounded full scan, never to a wrong answer.
        self.honour_search = True

    def install(self, controller: FakeOmadaController) -> HotspotClientsTable:
        controller.routes[f"/sites/{SITE_ID}/clients"] = self._list
        controller.routes["/disconnect"] = self._disconnect
        return self

    # -- endpoints ---------------------------------------------------------

    def _list(self, request: httpx.Request) -> httpx.Response:
        params = request.url.params
        self.list_queries.append(params)
        search = params.get("searchKey") if self.honour_search else None
        matching = [
            r
            for r in self.rows
            if search is None or search.lower() in str(r["mac"]).lower()
        ]
        # The real endpoint reads only these two names. Anything else and
        # the caller gets page 1 at the default size, with errorCode 0.
        try:
            page = int(params.get("currentPage") or 1)
        except ValueError:
            page = 1
        try:
            size = int(params.get("currentPageSize") or 10)
        except ValueError:
            size = 10
        start = (page - 1) * size
        window = matching[start : start + size]
        return httpx.Response(
            200,
            json=envelope(
                {
                    "totalRows": len(matching),
                    "currentPage": page,
                    "currentSize": size,
                    "data": window,
                }
            ),
        )

    def _disconnect(self, request: httpx.Request) -> httpx.Response:
        record_id = str(request.url.path).rsplit("/", 2)[-2]
        if self.disconnect_error is not None:
            code, message = self.disconnect_error
            return httpx.Response(200, json=envelope(error_code=code, msg=message))
        target = next((r for r in self.rows if r["id"] == record_id), None)
        if target is None:
            return httpx.Response(
                200,
                json=envelope(error_code=-1001, msg="Auth record does not exist."),
            )
        # Measured: the row survives, ``valid`` flips, ``end`` is rewritten.
        target["valid"] = False
        self.disconnected.append(record_id)
        return httpx.Response(200, json=envelope(msg="Success."))


def legacy_creds():
    return make_creds(ControllerAuthMode.LEGACY)


# --- the happy path --------------------------------------------------------


async def test_it_ends_the_live_authorization_for_that_mac():
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)

    result = await _adapter(controller).deauthorize_guest(
        legacy_creds(), SITE_ID, GUEST_MAC
    )

    assert result is True
    assert table.disconnected == ["rec-live"]
    disconnect = controller.request_for("/disconnect")
    assert disconnect.method == "POST"
    assert str(disconnect.url.path) == (
        f"/{OMADAC_ID}/api/v2/hotspot/sites/{SITE_ID}"
        "/cmd/clients/rec-live/disconnect"
    )
    # Empty body: the endpoint takes none, and inventing fields for a write
    # is how a firmware revision starts rejecting them.
    assert json.loads(disconnect.content) == {}


async def test_it_uses_the_operator_session_not_open_api():
    """The disconnect rides the same hotspot session ``extPortal/auth`` opens.

    Asserted because it is the whole reason this works on a legacy
    integration: if it ever started needing an Open API token, every
    hotspot-operator venue would lose the feature silently.
    """
    controller = FakeOmadaController()
    HotspotClientsTable([row("rec-live")]).install(controller)

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert controller.login_count == 1
    assert controller.token_count == 0
    assert controller.refresh_count == 0


async def test_a_mac_in_colon_form_still_finds_a_hyphenated_row():
    """The platform stores colons; the controller returns hyphens."""
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)

    await _adapter(controller).deauthorize_guest(
        legacy_creds(), SITE_ID, "aa:bb:cc:dd:ee:77"
    )

    assert table.disconnected == ["rec-live"]


# --- which row: the quiet-failure tests ------------------------------------


async def test_an_already_ended_row_for_the_same_mac_is_not_mistaken_for_the_live_one():
    """The bug this whole module is shaped to avoid.

    A returning guest has rows from previous visits. Ending one of those
    returns ``errorCode: 0`` from the controller -- a real success, against
    a row that was already over -- while the live grant keeps forwarding
    traffic. Matching must be MAC **and** ``valid``.
    """
    controller = FakeOmadaController()
    table = HotspotClientsTable(
        [
            row("rec-last-tuesday", valid=False, duration=1163),
            row("rec-live"),
        ]
    ).install(controller)

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert table.disconnected == ["rec-live"]


async def test_every_live_row_for_the_mac_is_ended_not_only_the_newest():
    """One device can hold more than one live grant -- re-authorizing while
    an earlier one is still running is the ordinary way that happens."""
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-older"), row("rec-newer")]).install(
        controller
    )

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert sorted(table.disconnected) == ["rec-newer", "rec-older"]


async def test_another_guests_live_row_is_left_alone():
    controller = FakeOmadaController()
    table = HotspotClientsTable(
        [row("rec-someone-else", mac="11-22-33-44-55-66"), row("rec-live")]
    ).install(controller)

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert table.disconnected == ["rec-live"]


# --- paging ----------------------------------------------------------------


async def test_it_pages_with_the_legacy_parameter_names():
    """``currentPage``/``currentPageSize``, not ``page``/``pageSize``.

    The wrong pair is not an error -- the controller answers ``errorCode:
    0`` with page 1 at size 10 -- so nothing but this assertion stands
    between the code and a scan that silently stops after ten rows.
    """
    controller = FakeOmadaController()
    HotspotClientsTable([row("rec-live")]).install(controller)

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    query = controller.request_for(f"/sites/{SITE_ID}/clients").url.params
    assert query.get("currentPage") == "1"
    assert query.get("currentPageSize") == str(PAGE_SIZE)
    assert "page" not in query
    assert "pageSize" not in query


async def test_a_guest_past_the_first_page_is_still_found():
    controller = FakeOmadaController()
    rows = [row(f"rec-other-{i}", mac=f"11-22-33-44-55-{i:02X}") for i in range(PAGE_SIZE)]
    rows.append(row("rec-live"))
    table = HotspotClientsTable(rows).install(controller)

    # searchKey is an optimization only; correctness must survive a
    # firmware that ignores it, so this table ignores it for this test --
    # which is also what forces the walk onto a second page.
    table.honour_search = False

    await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert table.disconnected == ["rec-live"]
    assert len(table.list_queries) >= 2


# --- "already not authorized" is success -----------------------------------


async def test_a_mac_with_no_live_row_is_success_and_sends_no_write():
    """Already not authorized is the end state the caller asked for.

    Raising here would make "disconnect a guest whose hour ran out" an
    error in a dashboard, and would make the button non-idempotent.
    """
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-expired", valid=False)]).install(controller)

    result = await _adapter(controller).deauthorize_guest(
        legacy_creds(), SITE_ID, GUEST_MAC
    )

    assert result is True
    assert table.disconnected == []
    assert not any(p.endswith("/disconnect") for p in controller.paths())


async def test_an_empty_table_is_success():
    controller = FakeOmadaController()
    HotspotClientsTable([]).install(controller)

    assert (
        await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)
        is True
    )


async def test_a_row_that_vanished_between_the_list_and_the_post_is_success():
    """The race: an operator ended it in the controller UI, or the guest's
    grant expired, or somebody double-clicked. All three mean the access is
    over, which is what was asked for."""
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)
    table.disconnect_error = (-1001, "Auth record does not exist.")

    assert (
        await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)
        is True
    )


# --- failing loudly --------------------------------------------------------


async def test_a_moved_endpoint_raises_rather_than_reporting_a_revocation():
    """Neither path is documented by TP-Link, so a firmware may move them.

    ``-1600 "Unsupported request path."`` must reach the caller. Reporting
    success here would be the exact falsehood the previous
    always-refuse implementation was protecting against.
    """
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)
    table.disconnect_error = (-1600, "Unsupported request path.")

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"


async def test_an_unexpected_controller_error_propagates():
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)
    table.disconnect_error = (-44112, "Something else entirely.")

    with pytest.raises(OmadaError):
        await _adapter(controller).deauthorize_guest(legacy_creds(), SITE_ID, GUEST_MAC)


# --- the one honest refusal ------------------------------------------------


async def test_open_api_credentials_alone_refuse_and_send_nothing():
    """Open API can read the controller and cannot open a hotspot session.

    The refusal is honest rather than a silent no-op, and -- the property
    worth keeping -- the same missing credential also makes
    ``authorize_guest`` refuse, so an integration that cannot disconnect a
    guest never connected one.
    """
    controller = FakeOmadaController()
    HotspotClientsTable([row("rec-live")]).install(controller)

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).deauthorize_guest(
            make_creds(ControllerAuthMode.OPENAPI), SITE_ID, GUEST_MAC
        )

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"
    assert "operator" in str(excinfo.value).lower()
    assert controller.requests == []


async def test_open_api_with_operator_credentials_does_disconnect():
    """The configuration real deployments use: Open API for inventory, an
    operator account for the portal. Both halves of the portal flow --
    authorize and disconnect -- run on the operator session."""
    controller = FakeOmadaController()
    table = HotspotClientsTable([row("rec-live")]).install(controller)

    result = await _adapter(controller).deauthorize_guest(
        make_creds(
            ControllerAuthMode.OPENAPI,
            username="wyfy-operator",
            password="s3cr3t-operator-pw",
        ),
        SITE_ID,
        GUEST_MAC,
    )

    assert result is True
    assert table.disconnected == ["rec-live"]
    assert controller.token_count == 0


# --- the pure matcher ------------------------------------------------------


def test_parse_authorized_client_reads_a_real_row():
    assert parse_authorized_client(row("rec-1")) == ("rec-1", GUEST_MAC, True)


def test_parse_authorized_client_normalizes_the_mac():
    parsed = parse_authorized_client(row("rec-1", mac="aa:bb:cc:dd:ee:77"))
    assert parsed == ("rec-1", GUEST_MAC, True)


def test_parse_authorized_client_rejects_a_row_it_could_not_act_on():
    assert parse_authorized_client({"mac": GUEST_MAC}) is None
    assert parse_authorized_client({"id": "rec-1"}) is None


def test_a_row_without_valid_is_treated_as_valid():
    """Refusing to disconnect anything would be the worse of the two
    failures if some firmware stopped sending the field."""
    bare = row("rec-1")
    del bare["valid"]
    assert parse_authorized_client(bare) == ("rec-1", GUEST_MAC, True)

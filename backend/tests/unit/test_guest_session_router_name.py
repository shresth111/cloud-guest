"""Tests for the guest-session list's Router column: ``GuestSessionResponse
.router_name``.

## The gap this closes

``GuestSessionResponse`` carried ``router_id`` (an opaque UUID) but no name,
so the customer dashboard's live-session list / Network Activity CSV had only
the id to show for the "Router" column. It rendered the raw UUID -- and for a
TP-Link Omada venue that UUID is the *synthetic fleet ``Router``* every one of
the venue's sessions runs against, which is meaningless to a customer.

The fix is the router-side twin of the ``device_mac`` denormalization
(``test_guest_mac_visibility``): the router serializer resolves the page's
distinct ``router_id``s to names in one bulk lookup and denormalizes the name
onto each row. These tests pin that resolution, its anti-N+1 dedupe (an Omada
page collapses to one id), and the honest ``None`` when a router row cannot be
resolved.

Every test here fails against the pre-fix code, where ``router_name`` did not
exist.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domains.guest.router import (
    _resolve_router_names,
    _session_responses,
)
from app.domains.guest.schemas import GuestSessionResponse

NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


class _Row:
    """Minimal attribute bag standing in for an ORM row -- the response
    builders only ever read attributes (see ``test_guest_mac_visibility``)."""

    def __init__(self, **fields: object) -> None:
        for key, value in fields.items():
            setattr(self, key, value)


def _session(**overrides: object) -> _Row:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "guest_id": uuid.uuid4(),
        "device_id": None,
        "router_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "auth_method": "otp",
        "voucher_id": None,
        "status": "active",
        "started_at": NOW,
        "ended_at": None,
        "last_activity_at": NOW,
        "ip_address": "10.5.50.246",
        "bytes_uploaded": 0,
        "bytes_downloaded": 0,
        "data_limit_mb": None,
        "session_timeout_minutes": None,
        "disconnect_reason": None,
        "disconnect_enforced": None,
        "user_agent": None,
        "created_at": NOW,
    }
    fields.update(overrides)
    return _Row(**fields)


class TestSessionResponseCarriesRouterName:
    def test_router_name_is_denormalized_onto_the_row(self) -> None:
        session = _session()
        [response] = _session_responses(
            [session],
            {},
            {str(session.router_id): "QA Omada Venue -- Fleet"},
        )
        assert response.router_name == "QA Omada Venue -- Fleet"
        # The id is kept alongside the name, never replaced -- it is the
        # stable key the "View router" link routes on.
        assert response.router_id == str(session.router_id)

    def test_absent_router_name_is_none_not_fabricated(self) -> None:
        session = _session()
        [response] = _session_responses([session], {}, {})
        assert response.router_name is None

    def test_router_names_arg_is_optional_for_back_compat(self) -> None:
        """Existing callers that pass only ``(sessions, macs)`` still work --
        the row simply carries no name."""
        session = _session()
        [response] = _session_responses([session], {})
        assert response.router_name is None

    def test_schema_defaults_router_name_to_none(self) -> None:
        """A payload built without the field (older producer) still parses."""
        response = GuestSessionResponse(
            id=str(uuid.uuid4()),
            guest_id=str(uuid.uuid4()),
            device_id=None,
            router_id=str(uuid.uuid4()),
            location_id=str(uuid.uuid4()),
            organization_id=str(uuid.uuid4()),
            auth_method="otp",
            voucher_id=None,
            status="active",
            started_at=NOW,
            ended_at=None,
            last_activity_at=NOW,
            ip_address=None,
            bytes_uploaded=0,
            bytes_downloaded=0,
            data_limit_mb=None,
            session_timeout_minutes=None,
            disconnect_reason=None,
            user_agent=None,
            created_at=NOW,
        )
        assert response.router_name is None


@pytest.mark.asyncio
class TestResolveRouterNames:
    async def test_one_bulk_lookup_for_a_whole_page(self) -> None:
        """40 sessions must cost one lookup, not 40 -- the same anti-N+1
        contract ``_resolve_session_macs`` holds for device MACs."""
        calls: list[list[uuid.UUID]] = []

        class _Service:
            async def list_router_names_for_ids(self, router_ids):
                calls.append(list(router_ids))
                return {}

        sessions = [_session() for _ in range(40)]
        await _resolve_router_names(sessions, service=_Service())

        assert len(calls) == 1
        assert len(calls[0]) == 40

    async def test_omada_page_collapses_to_one_id(self) -> None:
        """An Omada venue runs every session against ONE synthetic fleet
        router, so a page of many sessions must send that id once, not N
        times."""
        calls: list[list[uuid.UUID]] = []

        class _Service:
            async def list_router_names_for_ids(self, router_ids):
                calls.append(list(router_ids))
                return {}

        shared = uuid.uuid4()
        await _resolve_router_names(
            [_session(router_id=shared) for _ in range(30)],
            service=_Service(),
        )

        assert calls == [[shared]]

    async def test_no_sessions_means_no_query(self) -> None:
        class _Service:
            async def list_router_names_for_ids(self, router_ids):
                raise AssertionError("must not query for an empty page")

        result = await _resolve_router_names([], service=_Service())
        assert result == {}

    async def test_result_is_keyed_by_stringified_router_id(self) -> None:
        session = _session()
        name = "Reception AP"

        class _Service:
            async def list_router_names_for_ids(self, router_ids):
                return {rid: name for rid in router_ids}

        result = await _resolve_router_names([session], service=_Service())
        assert result == {str(session.router_id): name}

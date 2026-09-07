"""Regression tests for the reported defect "when a guest logs in with a
voucher, the MAC address doesn't appear -- not in Reports and not in Users".

## What the defect actually was

Not voucher-specific, and not missing data. ``login_via_voucher`` creates
and links a ``GuestDevice`` exactly like every other login path, and the
row is there. The MAC had **nowhere to travel in the response**:

* ``GuestResponse`` (the Users row) had no device field at all.
* ``GuestSessionResponse`` (the Reports row) had ``device_id`` -- an
  opaque UUID FK -- and no MAC.
* ``VoucherResponse`` has only a *self-reported* ``redeemed_identifier``
  and no link to the session that redeemed it.

Note also what it was **not**: masked. ``app.common.masking.mask_mac`` is
a documented no-op ("MAC addresses are shown unmasked platform-wide by
explicit product decision"), so ``MaskedMac`` routes the value through
one place without changing it. A blank MAC cell was always a missing
value, never a hidden one -- ``test_mac_is_not_hidden_by_masking`` below
pins that, because the whole triage hinged on it.

Every test here fails against the pre-fix code.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.common.masking import MaskedMac
from app.domains.guest.constants import (
    MAX_BULK_DEVICE_LOOKUP_IDS,
    MAX_BULK_VOUCHER_LOOKUP_IDS,
)
from app.domains.guest.exceptions import TooManyVoucherIdsError
from app.domains.guest.router import (
    _guest_response,
    _resolve_session_macs,
    _session_responses,
)
from app.domains.guest.schemas import (
    GuestResponse,
    GuestSessionResponse,
    VoucherRedemptionResponse,
)
from app.middleware.request_context import MaskingContext, masking_context

NOW = datetime(2026, 9, 7, 7, 38, 22, tzinfo=UTC)

# The real production values from the voucher login that triggered the
# report -- kept verbatim so a future reader can tie this file to the
# incident rather than to invented fixtures.
REAL_MAC = "DE:FD:67:99:02:29"
REAL_IP = "10.5.50.246"


class _Row:
    """Minimal attribute bag standing in for an ORM row.

    The router's response builders only ever read attributes, so this
    keeps the test honest about that boundary without dragging in a
    SQLAlchemy session for what is a pure serialization concern.
    """

    def __init__(self, **fields: object) -> None:
        for key, value in fields.items():
            setattr(self, key, value)


def _guest(guest_id: uuid.UUID | None = None, **overrides: object) -> _Row:
    fields: dict[str, object] = {
        "id": guest_id or uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": None,
        "identifier": "8824655613",
        "display_name": "Akhil Sharma",
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "total_visit_count": 1,
        "is_blocked": False,
        "blocked_reason": None,
        "created_at": NOW,
        "updated_at": NOW,
    }
    fields.update(overrides)
    return _Row(**fields)


def _device(mac: str, *, guest_id: uuid.UUID, last_seen_at: datetime) -> _Row:
    return _Row(
        id=uuid.uuid4(),
        guest_id=guest_id,
        mac_address=mac,
        device_name=None,
        first_seen_at=last_seen_at,
        last_seen_at=last_seen_at,
    )


def _session(**overrides: object) -> _Row:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "guest_id": uuid.uuid4(),
        "device_id": uuid.uuid4(),
        "router_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "auth_method": "voucher",
        "voucher_id": uuid.uuid4(),
        "status": "active",
        "started_at": NOW,
        "ended_at": None,
        "last_activity_at": NOW,
        "ip_address": REAL_IP,
        "bytes_uploaded": 0,
        "bytes_downloaded": 0,
        "data_limit_mb": None,
        "session_timeout_minutes": None,
        "disconnect_reason": None,
        "user_agent": None,
        "created_at": NOW,
    }
    fields.update(overrides)
    return _Row(**fields)


# ============================================================================
# Gap 1 -- Users: GuestResponse carried no device field at all
# ============================================================================


class TestGuestResponseCarriesMacs:
    def test_guest_response_exposes_the_guests_mac_addresses(self) -> None:
        """The Users row's whole defect: there was no field to put a MAC
        in, so the screen could not have shown one however it was
        rendered."""
        guest = _guest()
        device = _device(REAL_MAC, guest_id=guest.id, last_seen_at=NOW)

        payload = _guest_response(guest, devices=[device]).model_dump()

        assert payload["mac_addresses"] == [REAL_MAC]
        assert payload["device_count"] == 1

    def test_all_macs_are_returned_newest_first_not_just_one(self) -> None:
        """A guest may own several devices, so there is no single true
        "the MAC". The response returns every one, and the repository's
        ``last_seen_at DESC`` ordering is preserved, so ``[0]`` is the
        guest's current device -- which is what a single table cell
        should show."""
        guest = _guest()
        newest = _device(REAL_MAC, guest_id=guest.id, last_seen_at=NOW)
        older = _device(
            "AA:BB:CC:DD:EE:FF", guest_id=guest.id, last_seen_at=NOW - timedelta(days=3)
        )

        payload = _guest_response(guest, devices=[newest, older]).model_dump()

        assert payload["mac_addresses"] == [REAL_MAC, "AA:BB:CC:DD:EE:FF"]
        assert payload["device_count"] == 2

    def test_a_guest_with_no_device_reports_an_empty_list_not_a_placeholder(
        self,
    ) -> None:
        """Honest emptiness. A guest genuinely without a device must not
        borrow another guest's MAC or invent one."""
        payload = _guest_response(_guest(), devices=[]).model_dump()

        assert payload["mac_addresses"] == []
        assert payload["device_count"] == 0

    def test_guest_response_deliberately_has_no_ip_address_field(self) -> None:
        """An IP is a per-session DHCP lease, not a property of a person.
        Printing the last session's IP on a guest row would read as a
        current fact while meaning "whatever they held last Tuesday" --
        and that address very likely belongs to someone else by now.
        Asserted so a future change has to argue with this, not silently
        add the field. See ``GuestResponse``'s own docstring."""
        assert "ip_address" not in GuestResponse.model_fields


# ============================================================================
# Gap 2 -- Reports: GuestSessionResponse had a bare FK and no MAC
# ============================================================================


class TestSessionResponseCarriesMac:
    def test_session_response_exposes_a_readable_mac(self) -> None:
        session = _session()
        macs = {str(session.device_id): REAL_MAC}

        [payload] = [r.model_dump() for r in _session_responses([session], macs)]

        assert payload["device_mac"] == REAL_MAC

    def test_device_id_is_kept_alongside_the_mac(self) -> None:
        """``GET /guest-devices`` joins on ``device_id``; dropping it in
        favour of the MAC would have broken that endpoint's callers."""
        session = _session()

        [payload] = [
            r.model_dump()
            for r in _session_responses([session], {str(session.device_id): REAL_MAC})
        ]

        assert payload["device_id"] == str(session.device_id)

    def test_a_session_with_no_device_gets_none_not_a_borrowed_mac(self) -> None:
        no_device = _session(device_id=None)
        other = _session()

        payloads = [
            r.model_dump()
            for r in _session_responses(
                [no_device, other], {str(other.device_id): REAL_MAC}
            )
        ]

        assert payloads[0]["device_mac"] is None
        assert payloads[1]["device_mac"] == REAL_MAC

    def test_ip_address_was_already_being_served(self) -> None:
        """Half of the "and the IP too" request needed no backend change
        at all -- ``ip_address`` was already on this schema and already
        populated. Pinned so nobody re-adds it as though it were
        missing."""
        session = _session()

        [payload] = [r.model_dump() for r in _session_responses([session], {})]

        assert payload["ip_address"] == REAL_IP


class TestSessionMacResolutionIsNotAnNPlusOne:
    async def test_one_query_resolves_a_whole_page(self) -> None:
        """The reason this is denormalized server-side rather than
        resolved per row. 40 sessions must cost one lookup, not 40."""
        calls: list[list[uuid.UUID]] = []

        class _Service:
            async def list_devices_for_session_ids(self, *, device_ids, **_):
                calls.append(list(device_ids))
                return []

        sessions = [_session() for _ in range(40)]
        await _resolve_session_macs(
            sessions, service=_Service(), requesting_organization_id=None
        )

        assert len(calls) == 1
        assert len(calls[0]) == 40

    async def test_repeated_devices_are_deduplicated_before_querying(self) -> None:
        """One guest reconnecting all day produces many sessions on one
        device -- the common case, and it must not send the same id 30
        times."""
        calls: list[list[uuid.UUID]] = []

        class _Service:
            async def list_devices_for_session_ids(self, *, device_ids, **_):
                calls.append(list(device_ids))
                return []

        shared = uuid.uuid4()
        await _resolve_session_macs(
            [_session(device_id=shared) for _ in range(30)],
            service=_Service(),
            requesting_organization_id=None,
        )

        assert calls == [[shared]]

    async def test_no_devices_means_no_query_at_all(self) -> None:
        class _Service:
            async def list_devices_for_session_ids(self, **_):
                raise AssertionError("must not query when no session has a device")

        result = await _resolve_session_macs(
            [_session(device_id=None)],
            service=_Service(),
            requesting_organization_id=None,
        )

        assert result == {}

    async def test_resolution_is_scoped_through_the_session_not_the_device_owner(
        self,
    ) -> None:
        """A ``GuestDevice`` is reassignable -- ``mac_address`` is globally
        unique and ``get_or_create_device`` re-points ``guest_id`` with no
        organization check, by design. So one phone carried between two
        venues on different organizations ends up owned by whichever guest
        authenticated most recently.

        Scoping the MAC by the device's *current owner* would then blank
        org A's own session the moment that guest visits org B --
        reproducing the exact "empty cell that reads as missing data"
        symptom this change set exists to remove. The resolver must ask
        the session's question, not the device row's."""
        called: list[str] = []

        class _Service:
            async def list_devices_for_session_ids(self, **_):
                called.append("session_scoped")
                return []

            async def list_devices_by_ids(self, **_):
                called.append("owner_scoped")
                raise AssertionError(
                    "device_mac must not be scoped by the device's current "
                    "owner -- see GuestRepository.list_devices_for_session_ids"
                )

        await _resolve_session_macs(
            [_session()],
            service=_Service(),
            requesting_organization_id=uuid.uuid4(),
        )

        assert called == ["session_scoped"]

    async def test_an_unbounded_session_history_is_chunked_not_rejected(self) -> None:
        """``GET /guests/{id}`` resolves a guest's *entire* session
        history (``get_guest_sessions`` takes ``limit=None``). Passing
        that straight through would raise ``TooManyDeviceIdsError`` and
        turn a working detail endpoint into a 400 for the platform's
        heaviest users, so the resolver splits at the bound instead."""
        batch_sizes: list[int] = []

        class _Service:
            async def list_devices_for_session_ids(self, *, device_ids, **_):
                batch_sizes.append(len(device_ids))
                assert len(device_ids) <= MAX_BULK_DEVICE_LOOKUP_IDS
                return []

        sessions = [_session() for _ in range(MAX_BULK_DEVICE_LOOKUP_IDS + 25)]
        await _resolve_session_macs(
            sessions, service=_Service(), requesting_organization_id=None
        )

        assert batch_sizes == [MAX_BULK_DEVICE_LOOKUP_IDS, 25]


# ============================================================================
# Gap 3 -- Vouchers: no link from a voucher to the device that redeemed it
# ============================================================================


class TestVoucherRedemptionResolution:
    def test_redemption_carries_observed_device_and_address(self) -> None:
        payload = VoucherRedemptionResponse(
            voucher_id=str(uuid.uuid4()),
            session_count=1,
            session_id=str(uuid.uuid4()),
            guest_id=str(uuid.uuid4()),
            device_mac=REAL_MAC,
            ip_address=REAL_IP,
            started_at=NOW,
        ).model_dump()

        assert payload["device_mac"] == REAL_MAC
        assert payload["ip_address"] == REAL_IP

    def test_self_reported_identifier_is_not_mixed_into_observed_facts(self) -> None:
        """``Voucher.redeemed_identifier`` is whatever the guest typed at
        the portal; the MAC and IP here are observed by the platform. The
        two must not arrive in one shape that implies equal
        trustworthiness -- the one thing worse than a missing MAC is a
        made-up one presented as verified."""
        assert "redeemed_identifier" not in VoucherRedemptionResponse.model_fields

    def test_session_count_is_present_so_one_device_is_not_shown_as_the_redeemer(
        self,
    ) -> None:
        """A voucher can be multi-use. The response describes the most
        recent session only, so the count is what tells a UI not to
        present that device as *the* redeemer."""
        payload = VoucherRedemptionResponse(
            voucher_id=str(uuid.uuid4()),
            session_count=4,
            session_id=str(uuid.uuid4()),
            guest_id=str(uuid.uuid4()),
            device_mac=REAL_MAC,
            ip_address=REAL_IP,
            started_at=NOW,
        ).model_dump()

        assert payload["session_count"] == 4

    async def test_over_the_bound_raises_rather_than_truncating(self) -> None:
        """A silently dropped id renders as an empty cell that cannot be
        told apart from "never redeemed" -- the exact failure mode this
        whole change set exists to remove."""
        from app.domains.guest.service import GuestService

        service = GuestService.__new__(GuestService)
        with pytest.raises(TooManyVoucherIdsError):
            await service.list_voucher_redemptions(
                voucher_ids=[uuid.uuid4()] * (MAX_BULK_VOUCHER_LOOKUP_IDS + 1)
            )


class TestVoucherRedemptionsRouteWiring:
    """Inspects the real, wired ``RequirePermission`` closure rather than
    re-deriving what the decorator ought to say.

    Deliberately reads ``admin_router`` directly instead of booting the
    app with ``create_app()``, which is what the sibling
    ``test_guest_network_activity_log_router.py`` does. ``APIRoute``
    builds its ``dependant`` at construction time, so the router object
    already carries everything this needs -- and ``create_app()`` costs
    ~40s under CI's ``--cov=app`` and mutates global state (it overrides
    the OpenTelemetry TracerProvider, which logs a warning on every
    repeat call). Paying that, and layering more instrumentation onto
    shared objects, to learn a fact the router already knows would be a
    bad trade in a unit test."""

    @staticmethod
    def _permission_key_for_route(route) -> str | None:
        for dependency in route.dependant.dependencies:
            call = dependency.call
            freevars = getattr(call.__code__, "co_freevars", ())
            if "permission_key" in freevars:
                index = freevars.index("permission_key")
                return call.__closure__[index].cell_contents
        return None

    def _route(self, path: str):
        from app.domains.guest.router import admin_router

        return next(
            r
            for r in admin_router.routes
            if getattr(r, "path", None) == path
            and "GET" in getattr(r, "methods", set())
        )

    def test_route_is_registered_and_gated_on_guest_sessions_read(self) -> None:
        """Gated on ``guest_sessions.read``, not a voucher permission:
        everything it returns is guest-session data. A caller who may
        list vouchers but not read guest sessions must not reach session
        details through a voucher-shaped door."""
        route = self._route("/voucher-redemptions")

        assert self._permission_key_for_route(route) == "guest_sessions.read"

    def test_it_is_gated_exactly_like_the_sessions_list_it_draws_from(self) -> None:
        """Pinned as a relationship, not a literal, so that if
        ``GET /guest-sessions`` is ever re-gated this fails rather than
        silently leaving a cheaper door to the same data."""
        assert self._permission_key_for_route(
            self._route("/voucher-redemptions")
        ) == self._permission_key_for_route(self._route("/guest-sessions"))

    def test_the_voucher_domain_still_does_not_import_the_guest_domain(self) -> None:
        """``app.domains.voucher.models.Voucher``'s docstring is explicit
        that the guest module composes with it "never a shared table or
        FK". Resolving redemptions from the guest side is what keeps that
        true -- this pins the boundary so a later, easier-looking fix
        does not quietly invert it.

        Parsed with ``ast`` rather than grepped: the voucher module
        *describes* the guest domain in several docstrings (that is how
        the boundary is documented in the first place), so a text search
        would flag its own documentation as a violation.
        """
        import ast
        import pathlib

        import app.domains.voucher as voucher_pkg

        voucher_dir = pathlib.Path(voucher_pkg.__file__).parent
        offenders: list[str] = []
        for path in sorted(voucher_dir.glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                    "app.domains.guest"
                ):
                    offenders.append(f"{path.name}: from {node.module}")
                elif isinstance(node, ast.Import):
                    offenders.extend(
                        f"{path.name}: import {alias.name}"
                        for alias in node.names
                        if alias.name.startswith("app.domains.guest")
                    )

        assert offenders == []


# ============================================================================
# The triage question: missing, or masked?
# ============================================================================


class TestMacIsNotHiddenByMasking:
    """The founder was seeing a **missing** MAC, not a masked one, and
    the distinction decides what he should do about it. ``mask_mac`` is a
    documented no-op, so the unmask flow (``DataMaskingOtpDialog``) has
    no effect on a MAC whatsoever -- turning it on would not have made
    the value appear.
    """

    def test_mac_is_identical_with_masking_on_and_off(self) -> None:
        class _Model(GuestSessionResponse):
            pass

        session = _session()
        [response] = _session_responses([session], {str(session.device_id): REAL_MAC})

        token = masking_context.set(MaskingContext(masking_enabled=True))
        try:
            masked = response.model_dump()["device_mac"]
        finally:
            masking_context.reset(token)

        token = masking_context.set(MaskingContext(masking_enabled=False))
        try:
            unmasked = response.model_dump()["device_mac"]
        finally:
            masking_context.reset(token)

        assert masked == unmasked == REAL_MAC

    def test_guest_macs_are_also_unaffected_by_masking(self) -> None:
        guest = _guest()
        response = _guest_response(
            guest, devices=[_device(REAL_MAC, guest_id=guest.id, last_seen_at=NOW)]
        )

        token = masking_context.set(MaskingContext(masking_enabled=True))
        try:
            assert response.model_dump()["mac_addresses"] == [REAL_MAC]
        finally:
            masking_context.reset(token)

    def test_identifier_by_contrast_really_is_masked(self) -> None:
        """The control. Masking is genuinely working on the fields it
        applies to, which is why a masked ``identifier`` beside an
        unmasked MAC is a deliberate product decision and not the bug."""
        guest = _guest()

        token = masking_context.set(MaskingContext(masking_enabled=True))
        try:
            payload = _guest_response(guest, devices=[]).model_dump()
        finally:
            masking_context.reset(token)

        assert payload["identifier"] != "8824655613"
        assert payload["display_name"] == "Akhil S."

    def test_mac_fields_are_annotated_maskedmac_so_a_policy_change_reaches_them(
        self,
    ) -> None:
        """``mask_mac`` being a no-op today is a product decision, not an
        architectural one. Both new MAC surfaces are wired through
        ``MaskedMac`` so that if masking is ever reintroduced it applies
        here without hunting down call sites -- exactly the reason
        ``mask_mac`` was kept as a real function rather than deleted."""
        assert GuestSessionResponse.model_fields["device_mac"].annotation is not str
        session_ann = GuestSessionResponse.model_fields["device_mac"].metadata
        guest_ann = GuestResponse.model_fields["mac_addresses"]
        assert session_ann, "device_mac must carry the MaskedMac serializer"
        assert guest_ann.annotation == list[MaskedMac]

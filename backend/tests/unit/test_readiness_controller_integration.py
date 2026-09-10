"""A half-configured controller integration must be impossible to miss.

## The failure this closes

An operator finishes the Master onboarding wizard for a TP-Link Omada
controller and stops. They have to: listing the controller's sites needs
an authenticated call, which needs stored credentials, which need the
integration row the wizard is only creating at that moment -- so the
site/SSID mapping is a second visit to a different screen, and the wizard
says so and no more.

Everything then looks finished. The integration row exists, the fleet row
exists, the credentials work, and every sync succeeds. And
``authorize_portal_client`` refuses every guest at the venue, because
there is no ``external_site_id`` to send. Guests complete sign-in and have
no internet -- the same shape as the 2026-08-18 captive-portal incident,
arrived at from a different direction.

Two composed surfaces now say so, and this file covers the readiness half
(``tests/unit/test_network_integration.py::TestSyncAndBackoff`` covers the
other: the sync no longer calls such a venue ``CONNECTED``).

## Why the readiness checklist and not a new notification

An alert rule is opt-in -- a rule nobody created fires for nobody -- and
this codebase has a documented rule against backfilling rules fleet-wide.
The checklist is where an operator already goes to ask "is this venue
ready", it re-runs on every GET, and before this it answered a controller
with sixteen shrugs: seven NOT_APPLICABLE and nine unticked manual items.
Adding the one question that IS answerable turns a useless screen into
the one that names the problem.

## The tension with contract 11.5, stated deliberately

11.5 says a controller must never be reported as broken hardware. This
item reports a controller as failing -- and that is not a violation of it
but the same principle applied honestly. 11.5 forbids *false* reports:
running an agent-shaped check against a device with no agent. This check
reads three columns of a row this platform owns, and when it says the
venue authorizes nobody, the venue authorizes nobody.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.readiness.constants import (
    CHECKLIST_ITEMS,
    CHECKLIST_ITEMS_BY_KEY,
    CONTROLLER_MANAGED_ITEMS,
    DEFINITIONS_BY_KEY,
    ChecklistItemKey,
    ChecklistItemStatus,
    DetectionMode,
    checklist_items_for,
)
from app.domains.readiness.exceptions import UnknownChecklistItemError
from app.domains.readiness.service import ReadinessService

from .test_readiness import _build_service, _make_router

_OMADA = "tplink_omada"
_KEY = ChecklistItemKey.CONTROLLER_INTEGRATION.value


class _FakeIntegration:
    """Only the fields ``portal_readiness_gaps`` and the check read."""

    def __init__(
        self,
        *,
        credentials_encrypted: str | None = "cipher",
        location_id: uuid.UUID | None = None,
        external_site_id: str | None = "site-1",
        is_enabled: bool = True,
        status: str = "connected",
    ) -> None:
        self.id = uuid.uuid4()
        self.credentials_encrypted = credentials_encrypted
        self.location_id = location_id or uuid.uuid4()
        self.external_site_id = external_site_id
        self.is_enabled = is_enabled
        self.status = status


class _FakeIntegrationLookup:
    def __init__(self, integration: _FakeIntegration | None = None) -> None:
        self.integration = integration
        self.calls: list[uuid.UUID] = []

    async def find_integration_for_router(self, router_id: uuid.UUID):
        self.calls.append(router_id)
        return self.integration


async def _checklist(
    *,
    vendor: str = _OMADA,
    integration: _FakeIntegration | None = None,
    wire_lookup: bool = True,
):
    service, repo, router_lookup, isp, wg, agent = _build_service()
    lookup = _FakeIntegrationLookup(integration)
    if wire_lookup:
        # `_build_service` predates this collaborator and is shared with
        # every other readiness test, so the lookup is wired by rebuilding
        # here rather than by changing that helper's signature -- which
        # would also silently give the unwired case coverage it must not
        # have.
        service = ReadinessService(
            repo,
            router_lookup,
            isp,
            wg,
            agent,
            network_integration_lookup=lookup,
        )
    router = _make_router(status="pending_provisioning")
    router.vendor = vendor
    router_lookup.add(router)
    rows = await service.get_checklist(router.id, requesting_organization_id=None)
    return {row.item_key: row for row in rows}, lookup, service, rows


# ============================================================================
# The item exists only where it means something
# ============================================================================


class TestTheItemIsScopedToControllers:
    async def test_a_controller_gets_the_item(self) -> None:
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration()
        )
        assert _KEY in by_key

    async def test_a_mikrotik_does_not_get_the_item_at_all(self) -> None:
        """Not "gets it as NOT_APPLICABLE" -- does not get it. A
        seventeenth row on every existing customer's readiness page, to
        carry a question their hardware cannot be asked, would change the
        summary counts for the whole installed base."""
        by_key, _lookup, _service, _rows = await _checklist(vendor="mikrotik")
        assert _KEY not in by_key

    async def test_a_mikrotiks_checklist_is_byte_identical_to_before(self) -> None:
        by_key, _lookup, _service, rows = await _checklist(vendor="mikrotik")
        assert [row.item_key for row in rows] == [
            item.key.value for item in CHECKLIST_ITEMS
        ]

    async def test_the_lookup_is_never_called_for_an_agent_managed_router(
        self,
    ) -> None:
        """Not merely unused -- unreached. A MikroTik's checklist must not
        pay for a query about a table it has no row in."""
        _by_key, lookup, _service, _rows = await _checklist(vendor="mikrotik")
        assert lookup.calls == []

    def test_the_registry_helper_returns_the_same_object_for_agent_managed(
        self,
    ) -> None:
        """Identity, not equality: the agent-managed answer has to be the
        exact tuple that existed before any of this, in the same order."""
        assert checklist_items_for(agent_managed=True) is CHECKLIST_ITEMS

    def test_a_controller_gets_the_shared_items_plus_the_extra_one(self) -> None:
        items = checklist_items_for(agent_managed=False)
        assert items[: len(CHECKLIST_ITEMS)] == CHECKLIST_ITEMS
        assert items[len(CHECKLIST_ITEMS) :] == CONTROLLER_MANAGED_ITEMS


# ============================================================================
# What it reports
# ============================================================================


class TestWhatTheItemReports:
    async def test_a_finished_integration_passes(self) -> None:
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration()
        )
        assert by_key[_KEY].status == ChecklistItemStatus.PASS.value

    async def test_no_linked_integration_at_all_fails(self) -> None:
        """A fleet row registered as a controller with nothing behind it.
        Its venue's guests have a `router_id` and nowhere to be
        authorized."""
        by_key, _lookup, _service, _rows = await _checklist(integration=None)
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.FAIL.value
        assert "no network integration linked" in (row.detail or "")

    async def test_the_site_that_was_never_selected_fails(self) -> None:
        """The exact abandoned-wizard state, and the reason this file
        exists."""
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration(external_site_id=None)
        )
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.FAIL.value
        assert "no controller site has been selected" in (row.detail or "")

    async def test_an_unmapped_location_fails(self) -> None:
        """`find_enabled_integration_for_location` resolves by
        (organization, location, provider), so a NULL `location_id` means
        this row is selected for no venue -- documented on the column
        itself and easy to read as "organization-wide" instead."""
        # `_FakeIntegration(location_id=None)` substitutes a real uuid --
        # that parameter means "pick one for me" -- so the unmapped case is
        # built explicitly.
        integration = _FakeIntegration()
        integration.location_id = None
        by_key, _lookup, _service, _rows = await _checklist(integration=integration)
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.FAIL.value
        assert "not mapped to a location" in (row.detail or "")

    async def test_missing_credentials_fail(self) -> None:
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration(credentials_encrypted=None)
        )
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.FAIL.value
        assert "no controller credentials" in (row.detail or "")

    async def test_a_switched_off_integration_is_reported_as_switched_off(
        self,
    ) -> None:
        """Not folded into the gaps. "Somebody disabled this" and "somebody
        never finished this" send an operator to two different places, and
        telling the first one to go and finish the mapping wastes their
        time on work that is already done."""
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration(is_enabled=False)
        )
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.FAIL.value
        assert "switched off" in (row.detail or "")
        assert "cannot authorize any guest" not in (row.detail or "")

    async def test_the_detail_says_what_it_costs_the_guest(self) -> None:
        """A field name is a task; a consequence is a priority."""
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration(external_site_id=None)
        )
        assert "still have no internet" in (by_key[_KEY].detail or "")

    async def test_the_evidence_names_the_gaps_machine_readably(self) -> None:
        by_key, _lookup, _service, _rows = await _checklist(
            integration=_FakeIntegration(external_site_id=None)
        )
        assert by_key[_KEY].evidence["readiness_gaps"] == ["site_not_selected"]

    async def test_a_missing_ssid_does_not_fail_the_check(self) -> None:
        """`guest_ssid_id` is a step in the wizard and is read by nothing
        on the authorize path -- the SSID name arrives in the controller's
        own redirect. Verified against `authorize_portal_client`, not
        against the setup screens. Failing on it would send an operator to
        fix something that was never stopping anyone."""
        integration = _FakeIntegration()
        integration.guest_ssid_id = None
        by_key, _lookup, _service, _rows = await _checklist(integration=integration)
        assert by_key[_KEY].status == ChecklistItemStatus.PASS.value


# ============================================================================
# It must not be able to produce a false green
# ============================================================================


class TestItCannotFakeAPass:
    async def test_an_unwired_lookup_reports_not_checked_never_pass(self) -> None:
        """A collaborator nobody supplied is an unanswered question, not a
        healthy venue -- the posture ROGUE_DHCP_GUARD already takes."""
        by_key, _lookup, _service, _rows = await _checklist(
            integration=None, wire_lookup=False
        )
        row = by_key[_KEY]
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value
        assert row.status != ChecklistItemStatus.PASS.value
        assert "not wired" in (row.detail or "")

    async def test_an_operator_cannot_tick_it_by_hand(self) -> None:
        """Every other item is a claim a human can make from the outside.
        This one is computed from rows this platform owns, and a manual
        override would put the green badge back over the dead venue --
        which is the whole failure."""
        service, _repo, router_lookup, *_ = _build_service()
        router = _make_router(status="pending_provisioning")
        router.vendor = _OMADA
        router_lookup.add(router)

        with pytest.raises(UnknownChecklistItemError):
            await service.confirm_item(
                router.id,
                _KEY,
                status=ChecklistItemStatus.MANUALLY_CONFIRMED,
                detail="looks fine to me",
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=None,
            )

    async def test_a_manual_item_on_the_same_checklist_can_still_be_ticked(
        self,
    ) -> None:
        """The refusal above has to be about this one item, not a
        side-effect that broke manual confirmation for controllers."""
        service, _repo, router_lookup, *_ = _build_service()
        router = _make_router(status="pending_provisioning")
        router.vendor = _OMADA
        router_lookup.add(router)

        row = await service.confirm_item(
            router.id,
            ChecklistItemKey.GUEST_SIGN_IN.value,
            status=ChecklistItemStatus.MANUALLY_CONFIRMED,
            detail="tested on site",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
        )
        assert row.status == ChecklistItemStatus.MANUALLY_CONFIRMED.value


# ============================================================================
# It has to reach the summary, or nothing on the page changes colour
# ============================================================================


class TestItReachesTheSummary:
    async def test_a_dead_venue_is_counted_as_failing(self) -> None:
        """`NOT_APPLICABLE` is excluded from both counts, so before this a
        controller's summary was `failing: 0, passing: 0` no matter what
        state its integration was in -- a readiness page that could not go
        red."""
        _by_key, _lookup, service, rows = await _checklist(
            integration=_FakeIntegration(external_site_id=None)
        )
        summary = service.summarize(rows)
        assert summary["failing"] == 1
        assert summary["passing"] == 0

    async def test_a_finished_venue_is_counted_as_passing(self) -> None:
        _by_key, _lookup, service, rows = await _checklist(
            integration=_FakeIntegration()
        )
        summary = service.summarize(rows)
        assert summary["passing"] == 1
        assert summary["failing"] == 0

    async def test_the_item_is_auto_detected_so_it_re_runs_on_every_read(
        self,
    ) -> None:
        """A MANUAL item would freeze at whatever it said the first time,
        which for a venue somebody later half-broke is the same silence
        again."""
        assert CONTROLLER_MANAGED_ITEMS[0].detection_mode == DetectionMode.AUTO

    async def test_finishing_the_setup_flips_it_on_the_next_read(self) -> None:
        """The state has to be able to leave, not only arrive."""
        integration = _FakeIntegration(external_site_id=None)
        service, repo, router_lookup, isp, wg, agent = _build_service()
        lookup = _FakeIntegrationLookup(integration)
        service = ReadinessService(
            repo, router_lookup, isp, wg, agent, network_integration_lookup=lookup
        )
        router = _make_router(status="pending_provisioning")
        router.vendor = _OMADA
        router_lookup.add(router)

        first = {
            r.item_key: r
            for r in await service.get_checklist(
                router.id, requesting_organization_id=None
            )
        }
        assert first[_KEY].status == ChecklistItemStatus.FAIL.value

        integration.external_site_id = "site-1"
        second = {
            r.item_key: r
            for r in await service.get_checklist(
                router.id, requesting_organization_id=None
            )
        }
        assert second[_KEY].status == ChecklistItemStatus.PASS.value


# ============================================================================
# The serializer has to know about it, or the page 500s on the one row
# that matters
# ============================================================================


class TestTheRowCanActuallyBeRendered:
    """Caught in review, not by the tests above -- which is the point of
    writing it down here.

    `CONTROLLER_INTEGRATION` is deliberately absent from
    `CHECKLIST_ITEMS_BY_KEY` so `confirm_item` refuses a manual override.
    `router._item_response` was looking definitions up in that same
    mapping, so the first controller checklist ever fetched would have
    raised `KeyError` and returned a 500 -- a screen that fails outright
    instead of one that reports the venue. Every service-level test above
    passed throughout, because none of them go through the serializer.
    """

    def test_the_serializer_can_render_every_item_a_checklist_can_contain(
        self,
    ) -> None:
        from app.domains.readiness.models import RouterChecklistItem
        from app.domains.readiness.router import _item_response

        for agent_managed in (True, False):
            for definition in checklist_items_for(agent_managed=agent_managed):
                row = RouterChecklistItem(
                    router_id=uuid.uuid4(),
                    item_key=definition.key.value,
                    status=ChecklistItemStatus.NOT_CHECKED.value,
                    detection_mode=definition.detection_mode.value,
                    detail=None,
                    evidence={},
                    last_checked_at=None,
                    checked_by_user_id=None,
                )
                response = _item_response(row)
                assert response.item_key == definition.key.value
                assert response.label == definition.label

    def test_the_display_mapping_covers_both_registries(self) -> None:
        for definition in CHECKLIST_ITEMS + CONTROLLER_MANAGED_ITEMS:
            assert definition.key in DEFINITIONS_BY_KEY

    def test_the_confirmable_mapping_deliberately_does_not(self) -> None:
        """The two mappings answer two questions and must not be merged."""
        assert ChecklistItemKey.CONTROLLER_INTEGRATION in DEFINITIONS_BY_KEY
        assert ChecklistItemKey.CONTROLLER_INTEGRATION not in CHECKLIST_ITEMS_BY_KEY

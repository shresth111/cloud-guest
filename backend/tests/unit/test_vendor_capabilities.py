"""Vendor gating -- contract §11.5.

The failure this whole module guards against is not a crash. It is a
perfectly healthy TP-Link Omada venue being reported as a MikroTik that is
offline, unprovisioned and failing seven readiness checks, because an
Omada controller is registered as a ``Router`` row (contract §11.3) and
every agent-assuming sweep in the product predates that possibility.

So these tests are mostly *not* about the three predicates, which are
nearly trivial. They are about the three call sites, which are not: each
one is a surface an operator reads and believes.

The predicates themselves get one property tested carefully -- that the
answer for every existing vendor is unchanged -- because the migration
requirement is that customers with no Omada anywhere see no behavior
change at all.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from app.domains.readiness.constants import (
    CHECKLIST_ITEMS,
    CONTROLLER_MANAGED_ITEMS,
    ChecklistItemStatus,
    DetectionMode,
)
from app.domains.router.exceptions import RouterVendorNotProvisionableError
from app.domains.router.vendor_capabilities import (
    CONTROLLER_MANAGED_VENDORS,
    NOT_APPLICABLE_REASON,
    is_agent_managed,
    is_controller_managed,
    supports_zero_touch_provisioning,
    vendor_of,
)

# The vendors that existed before Omada. Every one of them must keep
# answering exactly as it did, which is the whole backward-compatibility
# requirement in one list.
_PRE_EXISTING_VENDORS = ("mikrotik", "ruckus", "unifi", "aruba", "cisco_meraki")

_OMADA = "tplink_omada"


@dataclass
class _Row:
    """Anything with a ``vendor``, which is all these predicates read."""

    vendor: str


# ============================================================================
# The predicates
# ============================================================================


class TestVendorOf:
    def test_a_bare_string_is_returned_as_is(self) -> None:
        assert vendor_of(_OMADA) == _OMADA

    def test_a_row_is_read_through_its_vendor_attribute(self) -> None:
        assert vendor_of(_Row(vendor=_OMADA)) == _OMADA

    def test_a_row_with_no_vendor_reads_as_the_column_default(self) -> None:
        """These predicates run inside health sweeps that iterate a whole
        fleet. One malformed row must not stop the sweep reporting on every
        other one, so this answers rather than raises -- and it answers
        with the value the column itself defaults to, which is the only
        answer that cannot invent a capability."""

        class _Bare:
            pass

        assert vendor_of(_Bare()) == "mikrotik"
        assert vendor_of(None) == "mikrotik"

    def test_a_non_string_vendor_reads_as_the_column_default(self) -> None:
        assert vendor_of(_Row(vendor=None)) == "mikrotik"  # type: ignore[arg-type]


class TestTheAnswerForExistingVendorsIsUnchanged:
    """The migration requirement, as a test.

    An existing customer has no Omada anywhere. Every predicate must
    therefore answer for their rows exactly as the code did before this
    module existed -- when there was no question and everything was
    assumed to run an agent.
    """

    @pytest.mark.parametrize("vendor", _PRE_EXISTING_VENDORS)
    def test_every_pre_existing_vendor_is_agent_managed(self, vendor: str) -> None:
        assert is_agent_managed(vendor) is True
        assert is_controller_managed(vendor) is False
        assert supports_zero_touch_provisioning(vendor) is True

    def test_an_unknown_vendor_is_treated_as_agent_managed(self) -> None:
        """The complement is open on purpose (see the module docstring).
        A vendor string nobody anticipated keeps its old behavior rather
        than silently losing its readiness checks and its provisioning
        path -- failing open toward "check it" is the safe direction here,
        because the cost is a failing check an operator can see rather
        than a missing one they cannot."""
        assert is_agent_managed("some_vendor_added_in_2027") is True


class TestOmadaIsControllerManaged:
    def test_the_predicates_agree(self) -> None:
        assert is_controller_managed(_OMADA) is True
        assert is_agent_managed(_OMADA) is False
        assert supports_zero_touch_provisioning(_OMADA) is False

    def test_the_row_form_and_the_string_form_agree(self) -> None:
        """Both call shapes are in real use -- the service layers hold a
        row, `network_integration` holds only a string -- and a predicate
        that answered differently for the two would be a gate that is on
        in one place and off in another."""
        assert is_controller_managed(_Row(vendor=_OMADA)) is True
        assert is_agent_managed(_Row(vendor=_OMADA)) is False

    def test_the_fleet_vendor_string_matches_the_integration_domains(self) -> None:
        """The two domains spell this vendor independently -- one in a
        gating set, one in a translation table -- and if they ever drift
        the gate silently stops matching the rows it is meant to gate."""
        from app.domains.network_integration.constants import (
            ROUTER_VENDOR_BY_PROVIDER,
        )

        assert set(ROUTER_VENDOR_BY_PROVIDER.values()) <= CONTROLLER_MANAGED_VENDORS


# ============================================================================
# Call site 1: the readiness checklist
# ============================================================================


class TestReadinessChecklist:
    """A controller has no agent, no WireGuard peer and no RouterOS API, so
    every AUTO item has no answer rather than a failing one."""

    async def _checklist(self, vendor: str):
        from tests.unit.test_readiness import (
            _build_service,
            _make_router,
            make_controller_router,
        )

        service, _repo, router_lookup, *_ = _build_service()
        if vendor == _OMADA:
            router = make_controller_router(status="pending_provisioning")
        else:
            router = _make_router(status="pending_provisioning")
            router.vendor = vendor
        router_lookup.add(router)
        return await service.get_checklist(
            router.id, requesting_organization_id=None
        )

    async def test_every_auto_item_is_not_applicable_for_a_controller(self) -> None:
        rows = await self._checklist(_OMADA)
        auto_keys = {
            item.key.value
            for item in CHECKLIST_ITEMS
            if item.detection_mode == DetectionMode.AUTO
        }
        by_key = {row.item_key: row for row in rows}
        for key in auto_keys:
            assert by_key[key].status == ChecklistItemStatus.NOT_APPLICABLE.value, key

    async def test_not_a_single_auto_item_reads_as_failing(self) -> None:
        """The specific outcome §11.5 says must not ship: a working venue
        rendered as a broken one.

        The one item that CAN fail for a controller is
        CONTROLLER_INTEGRATION, and only when the venue really is dead --
        no integration linked, or one that authorizes nobody. It is
        NOT_CHECKED here because `_build_service` supplies no
        network-integration lookup; `test_readiness_controller_integration
        .py` covers the states it does report.
        """
        rows = await self._checklist(_OMADA)
        assert not [
            r for r in rows if r.status == ChecklistItemStatus.FAIL.value
        ]

    async def test_the_reason_says_why_rather_than_leaving_it_blank(self) -> None:
        """An empty checklist that says nothing looks like one that has not
        run yet, which sends an operator looking for a problem that does
        not exist."""
        rows = await self._checklist(_OMADA)
        not_applicable = [
            r
            for r in rows
            if r.status == ChecklistItemStatus.NOT_APPLICABLE.value
        ]
        assert not_applicable
        for row in not_applicable:
            assert row.detail == NOT_APPLICABLE_REASON

    async def test_manual_items_are_left_alone(self) -> None:
        """An operator confirming "guest sign-in works at this venue" by
        hand is exactly as meaningful for an Omada site as for a MikroTik
        one, so the manual half of the checklist is untouched."""
        rows = await self._checklist(_OMADA)
        manual_keys = {
            item.key.value
            for item in CHECKLIST_ITEMS
            if item.detection_mode == DetectionMode.MANUAL
        }
        by_key = {row.item_key: row for row in rows}
        for key in manual_keys:
            assert by_key[key].status != ChecklistItemStatus.NOT_APPLICABLE.value

    async def test_a_mikrotik_still_gets_its_real_answers(self) -> None:
        """The gate must be narrow: an existing customer's fleet behaves
        exactly as it did."""
        rows = await self._checklist("mikrotik")
        assert not [
            r
            for r in rows
            if r.status == ChecklistItemStatus.NOT_APPLICABLE.value
        ]


class TestReadinessSummary:
    """``not_applicable`` is a fifth bucket, excluded from both of the
    counts a readiness percentage is built from."""

    async def test_not_applicable_is_counted_separately(self) -> None:
        from tests.unit.test_readiness import _build_service, make_controller_router

        service, _repo, router_lookup, *_ = _build_service()
        router = make_controller_router(status="pending_provisioning")
        router_lookup.add(router)

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )
        summary = service.summarize(rows)

        assert summary["not_applicable"] > 0
        # Not folded into either: claiming them as passing would assert
        # checks this platform never made, and counting them as failing
        # would report a healthy venue as broken.
        assert summary["failing"] == 0
        assert summary["passing"] == 0
        # `total` still counts every row, so a caller reading only the
        # original four buckets sees no change in any of them. A controller
        # gets one row MORE than the sixteen shared items -- the
        # CONTROLLER_INTEGRATION check, the one question that is answerable
        # for it (see `constants.CONTROLLER_MANAGED_ITEMS`). It reads
        # NOT_CHECKED here because `_build_service` wires no
        # network-integration lookup, which is itself the contract: a
        # collaborator that was not supplied must never produce a PASS.
        assert summary["total"] == len(CHECKLIST_ITEMS) + len(
            CONTROLLER_MANAGED_ITEMS
        )
        assert summary["not_checked"] == len(CONTROLLER_MANAGED_ITEMS) + len(
            [i for i in CHECKLIST_ITEMS if i.detection_mode == DetectionMode.MANUAL]
        )


# ============================================================================
# Call site 2: provisioning tokens
# ============================================================================


class TestProvisioningTokenIsRefused:
    async def test_a_controller_cannot_be_issued_a_provisioning_token(self) -> None:
        """A token minted for a device that runs no agent could never be
        redeemed, and the operator holding it would spend the afternoon
        wondering why."""
        from tests.unit.test_router import make_service

        service, _repository, location_lookup, *_ = make_service()
        location = location_lookup.add(organization_id=uuid.uuid4())
        router = await service.create_router(
            actor_user_id=None,
            location_id=location.id,
            requesting_organization_id=location.organization_id,
            name="Lobby controller",
            serial_number="OMADA-TESTSERIAL",
            mac_address="02:00:00:00:00:01",
            model="OC200",
            vendor=_OMADA,
        )

        with pytest.raises(RouterVendorNotProvisionableError):
            await service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=location.organization_id,
            )


# ============================================================================
# Call site 3: the ZTP dashboard
# ============================================================================


class TestZtpDashboardExcludesControllers:
    """Every stage this dashboard can report is a step in a workflow that
    begins with an enrollment request and ends with an agent checking in.
    A controller enters none of them and would sit at APPROVED forever,
    reading as a device someone forgot to finish provisioning.

    Reuses ``test_monitoring_ztp``'s own fakes rather than rolling a
    narrower one: this service reaches for four repository methods and a
    hand-made double that implements only the two the happy path touches
    would pass while testing a shape the real service does not have.
    """

    async def test_a_controller_row_is_not_listed(self) -> None:
        from app.domains.monitoring.service import ZtpMonitoringService
        from tests.unit.test_monitoring_ztp import FakeRouter, FakeZtpRepository

        @dataclass
        class _VendorRouter(FakeRouter):
            """``FakeRouter`` predates vendors entirely -- which is itself
            the point being tested elsewhere in this file: a row with no
            vendor attribute must read as the column default and keep its
            old behavior."""

            vendor: str = "mikrotik"

        now = datetime.now(UTC)
        omada = _VendorRouter(
            id=uuid.uuid4(),
            status="pending_provisioning",
            last_seen_at=None,
            serial_number="OMADA-AABBCC",
            mac_address="02:00:00:00:00:01",
            name="Lobby controller",
            vendor=_OMADA,
        )
        mikrotik = _VendorRouter(
            id=uuid.uuid4(),
            status="pending_provisioning",
            last_seen_at=now,
            serial_number="SN-2",
            mac_address="AA:BB:CC:DD:EE:02",
            name="Front desk router",
            vendor="mikrotik",
        )
        repo = FakeZtpRepository(routers=[omada, mikrotik])
        service = ZtpMonitoringService(repo)

        result = await service.get_dashboard(organization_id=None)

        # One MikroTik in, one MikroTik out -- the controller contributes
        # to no stage count and appears in no row.
        assert sum(result.stage_counts.values()) == 1
        assert result.total_items == 1
        assert [entry.router_id for entry in result.items] == [mikrotik.id]

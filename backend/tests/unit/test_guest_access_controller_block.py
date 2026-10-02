"""Blocking a guest at a controller-managed venue keeps their devices off
the WiFi, not only off the sign-in page -- and says, per device, what
actually happened.

## The gap these tests close

``BLOCKLIST`` rules were already vendor-neutral and already correct at the
gate: ``_reject_if_blocked`` and ``is_blocklisted`` refuse the person at
every login, at RADIUS authorize, and on the agent's authorized-MAC list.
Device-side enforcement meant *ending the live session*, which at an Omada
venue routes through the provider.

Nothing ever asked the controller to **block** the device. ``block_client``
and ``unblock_client`` existed as provider methods and as manual per-client
routes, and nothing in the blocklist path called either -- so a blocked
guest was disconnected once and could reconnect and use the network without
signing in again, wherever the venue's SSID allowed it.

## What is asserted, and what is deliberately not

Every test here asserts an observable: a call that reached a fake
controller, a row that was persisted, a row that a release found again. A
test that only checked "the enforcer has a blocker attached" would pass
against the bug, because the bug was that nothing was called.

Nothing here asserts what a block does to a guest who is holding a live
portal authorization at that moment. That is **unmeasured** on real hardware
(CAPABILITY-MATRIX §4.6) and nothing in this change claims it: ending the
live session is a separate mechanism with its own result.

## MikroTik

``TestMikroTikIsUntouched`` is the proof obligation for the whole change.
Its sibling file ``test_guest_access_block_enforcement.py`` is the larger
half of that proof -- all 31 of its tests run the RouterOS path and pass
unchanged, including
``TestRetryAndUnblock.test_unblocking_needs_no_device_work_because_nothing_was_left_there``,
which now also asserts that nothing was recorded for a controller to hold.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import pytest

from app.domains.guest_access.constants import (
    AccessRuleType,
    BlockEnforcementStatus,
)
from app.domains.guest_access.enforcement import (
    BlocklistEnforcer,
    ControllerBlockOutcome,
    ControllerReleaseOutcome,
)
from app.domains.guest_access.models import GuestAccessRule
from app.domains.guest_access.service import GuestAccessService

from .test_guest_access import FakeLocationLookup
from .test_guest_access_block_enforcement import (
    TERMINATED,
    FakeDevice,
    FakeDeviceAdapter,
    FakeGuest,
    FakeGuestAccessRepository,
    FakeRouter,
    FakeRouterLookup,
    FakeSession,
    FakeSessionLookup,
)

pytestmark = pytest.mark.asyncio

IDENTIFIER = "+919876543210"
PHONE_MAC = "AA:BB:CC:DD:EE:01"
LAPTOP_MAC = "AA:BB:CC:DD:EE:02"
TABLET_MAC = "AA:BB:CC:DD:EE:03"

#: Omada's own normalized "this client does not exist" code, as
#: ``network_integration.constants.ErrorCode.CLIENT_NOT_FOUND`` spells it.
#: Hard-coded rather than imported so a rename in that domain surfaces here
#: as a failing test rather than as two modules quietly agreeing on a
#: different string than the controller sends.
CLIENT_NOT_FOUND = "OMADA_CLIENT_NOT_FOUND"


# ============================================================================
# Test doubles
# ============================================================================


@dataclass
class FakeDeviceBlocker:
    """A venue's controller, as far as ``guest_access`` can see one.

    Structurally satisfies
    ``enforcement.ControllerDeviceBlockerProtocol``. It answers in exactly
    the four shapes the real hook answers in, because the point of the
    outcome type is that those four are different facts.
    """

    #: Locations that have a controller at all. Everything else is a venue
    #: this platform reaches over the router API, and must never be written
    #: to from here.
    controller_locations: set[uuid.UUID] = field(default_factory=set)
    #: MACs this controller has never heard of -> ``NOT_APPLICABLE``.
    unknown_macs: set[str] = field(default_factory=set)
    #: MACs this controller refuses -> ``FAILED``.
    refused_macs: set[str] = field(default_factory=set)
    #: When set, every action is refused with this reason -- the
    #: hotspot-operator (``legacy``) venue.
    unsupported_reason: str | None = None
    #: MACs whose *release* does not land.
    release_failures: set[str] = field(default_factory=set)

    presence_checks: list[uuid.UUID] = field(default_factory=list)
    blocked: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    released: list[tuple[uuid.UUID, str]] = field(default_factory=list)

    async def controller_present(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID | None
    ) -> bool:
        self.presence_checks.append(location_id)
        return location_id in self.controller_locations

    async def block_device(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> ControllerBlockOutcome:
        if self.unsupported_reason is not None:
            return ControllerBlockOutcome(
                location_id=location_id,
                mac_address=client_mac,
                status=BlockEnforcementStatus.UNENFORCED.value,
                error_message=self.unsupported_reason,
            )
        self.blocked.append((location_id, client_mac))
        if client_mac in self.unknown_macs:
            return ControllerBlockOutcome(
                location_id=location_id,
                mac_address=client_mac,
                status=BlockEnforcementStatus.NOT_APPLICABLE.value,
                error_code=CLIENT_NOT_FOUND,
                error_message="The controller does not know that client.",
            )
        if client_mac in self.refused_macs:
            return ControllerBlockOutcome(
                location_id=location_id,
                mac_address=client_mac,
                status=BlockEnforcementStatus.FAILED.value,
                error_code="OMADA_PERMISSION_DENIED",
                error_message="The controller refused.",
            )
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=client_mac,
            status=BlockEnforcementStatus.ENFORCED.value,
        )

    async def release_device(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> ControllerReleaseOutcome:
        self.released.append((location_id, client_mac))
        if client_mac in self.release_failures:
            return ControllerReleaseOutcome(
                released=False, error_message="The controller did not answer."
            )
        return ControllerReleaseOutcome(released=True)


@dataclass
class Fixture:
    service: GuestAccessService
    repository: FakeGuestAccessRepository
    session_lookup: FakeSessionLookup
    blocker: FakeDeviceBlocker
    adapter: FakeDeviceAdapter
    organization_id: uuid.UUID
    location_id: uuid.UUID
    other_location_id: uuid.UUID
    guest_id: uuid.UUID
    router_id: uuid.UUID


class _DeviceSessionLookup(FakeSessionLookup):
    """``FakeSessionLookup`` plus the one lookup a controller block needs.

    The real ``GuestRepository`` already has
    ``list_devices_for_guest_ids``; the sibling file's fake predates it and
    deliberately keeps it, because a RouterOS block must never reach this
    method at all.
    """

    guest_devices: dict[uuid.UUID, list[FakeDevice]]
    device_lookups: list[uuid.UUID]

    async def list_devices_for_guest_ids(
        self,
        *,
        guest_ids,  # noqa: ANN001
        organization_id: uuid.UUID | None,
    ) -> list[FakeDevice]:
        self.device_lookups.extend(guest_ids)
        found: list[FakeDevice] = []
        for guest_id in guest_ids:
            found.extend(self.guest_devices.get(guest_id, []))
        return found


def _build(
    *,
    macs: tuple[str, ...] = (PHONE_MAC,),
    online: bool = True,
    controller_venue: bool = True,
    blocker: FakeDeviceBlocker | None = None,
) -> Fixture:
    organization_id = uuid.uuid4()
    location_id = uuid.uuid4()
    other_location_id = uuid.uuid4()
    router_id = uuid.uuid4()
    guest_id = uuid.uuid4()
    device_id = uuid.uuid4()

    adapter = FakeDeviceAdapter()
    if online:
        adapter.active_users.add(IDENTIFIER)
        adapter.active_macs.add(macs[0])

    session_lookup = _DeviceSessionLookup(
        guests={
            (organization_id, IDENTIFIER): FakeGuest(id=guest_id, identifier=IDENTIFIER)
        },
        sessions={
            guest_id: (
                [
                    FakeSession(
                        id=uuid.uuid4(),
                        router_id=router_id,
                        device_id=device_id,
                        location_id=location_id,
                    )
                ]
                if online
                else []
            )
        },
        devices={device_id: FakeDevice(mac_address=macs[0])},
    )
    session_lookup.guest_devices = {
        guest_id: [FakeDevice(mac_address=mac) for mac in macs]
    }
    session_lookup.device_lookups = []

    blocker = blocker or FakeDeviceBlocker()
    if controller_venue:
        blocker.controller_locations.add(location_id)

    repository = FakeGuestAccessRepository()
    # `location_lookup` became required on `GuestAccessService` in the PR
    # that stopped a venue-confined admin writing a rule outside their
    # scope. This file's fixtures predate it: both PRs were green alone
    # and red together, which is what a required keyword-only argument
    # is for -- it fails loudly at construction instead of writing an
    # unscoped rule. The lookup knows this fixture's own venue.
    location_lookup = FakeLocationLookup()
    location_lookup.add(location_id, organization_id)
    location_lookup.add(other_location_id, organization_id)
    enforcer = BlocklistEnforcer(
        session_lookup=session_lookup,
        router_lookup=FakeRouterLookup(routers={router_id: FakeRouter(id=router_id)}),
        terminated_session_status=TERMINATED,
        adapter_factory=lambda vendor: adapter,
        device_blocker=blocker,
    )
    return Fixture(
        service=GuestAccessService(
            repository, block_enforcer=enforcer, location_lookup=location_lookup
        ),
        repository=repository,
        session_lookup=session_lookup,
        blocker=blocker,
        adapter=adapter,
        organization_id=organization_id,
        location_id=location_id,
        other_location_id=other_location_id,
        guest_id=guest_id,
        router_id=router_id,
    )


async def _block(fx: Fixture, **overrides: object) -> GuestAccessRule:
    kwargs: dict[str, object] = {
        "organization_id": fx.organization_id,
        "requesting_organization_id": fx.organization_id,
        "location_id": fx.location_id,
        "identifier": IDENTIFIER,
        "rule_type": AccessRuleType.BLOCKLIST,
        "reason": "abuse",
        "expires_at": None,
        "actor_user_id": uuid.uuid4(),
    }
    kwargs.update(overrides)
    return await fx.service.create_guest_rule(**kwargs)  # type: ignore[arg-type]


# ============================================================================
# One rule names a person; the controller blocks a MAC
# ============================================================================


class TestIdentifierResolvesToDevices:
    async def test_every_known_device_is_blocked_not_only_the_live_one(
        self,
    ) -> None:
        """The bridge this whole change is about.

        The rule carries a phone number. The guest holds three devices and
        is signed in on one of them. Blocking only the device holding the
        live session would leave the other two able to associate, which is
        exactly the reconnect this feature exists to stop.
        """
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC, TABLET_MAC))

        await _block(fx)

        assert [mac for _, mac in fx.blocker.blocked] == [
            PHONE_MAC,
            LAPTOP_MAC,
            TABLET_MAC,
        ]
        assert fx.session_lookup.device_lookups == [fx.guest_id]

    async def test_a_guest_who_has_never_connected_blocks_nothing_on_a_device(
        self,
    ) -> None:
        """Legitimate, and the reason these tables are identifier-keyed.

        A rule may be written for somebody who has never been here -- that
        is the point of keying on the login identifier rather than on a
        ``guest_id``. There is no device to name, so no controller is
        written to, and the platform rule is the whole enforcement. It is
        also sufficient: ``check_access`` refuses them at their first
        sign-in.
        """
        fx = _build()
        fx.session_lookup.guests = {}

        rule = await _block(fx)

        assert fx.blocker.blocked == []
        assert fx.repository.controller_blocks == []
        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value

    async def test_a_known_guest_with_no_recorded_device_blocks_nothing(
        self,
    ) -> None:
        """The other empty case, and a different one: the guest exists and
        has signed in, but no ``GuestDevice`` row was ever written (a login
        that carried no device MAC). Nothing to address, nothing claimed."""
        fx = _build(online=False)
        fx.session_lookup.guest_devices = {fx.guest_id: []}

        await _block(fx)

        assert fx.blocker.blocked == []
        assert fx.repository.controller_blocks == []

    async def test_a_guest_who_is_offline_is_still_blocked_on_the_controller(
        self,
    ) -> None:
        """Measured behaviour, not an assumption: a controller block lives
        on the known-client record, and a client that has been offline for
        hours can be blocked (CAPABILITY-MATRIX §4.3).

        So the feature must not depend on whether the guest happened to be
        online when the operator clicked. Before this, an offline guest
        returned "nothing to do" and the path stopped there.
        """
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC), online=False)

        await _block(fx)

        assert [mac for _, mac in fx.blocker.blocked] == [PHONE_MAC, LAPTOP_MAC]


# ============================================================================
# The outcome is per device, and honest
# ============================================================================


class TestThePerDeviceOutcome:
    async def test_a_partial_result_is_expressible(self) -> None:
        """Three of five. The single rule-level status cannot say this, and
        rounding it to one value is how a venue comes to believe five
        devices are blocked when three are."""
        blocker = FakeDeviceBlocker(
            unknown_macs={LAPTOP_MAC}, refused_macs={TABLET_MAC}
        )
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC, TABLET_MAC), blocker=blocker)

        rule = await _block(fx)

        by_mac = {b.mac_address: b for b in rule.controller_blocks}
        assert by_mac[PHONE_MAC].status == BlockEnforcementStatus.ENFORCED.value
        assert by_mac[LAPTOP_MAC].status == BlockEnforcementStatus.NOT_APPLICABLE.value
        assert by_mac[TABLET_MAC].status == BlockEnforcementStatus.FAILED.value

    async def test_unknown_to_the_controller_is_distinguishable_from_refused(
        self,
    ) -> None:
        """``performed: false`` conflates two facts and only one of them is
        actionable. "The venue's controller has never seen this phone" is
        not a problem; "the venue's controller refused to block this phone"
        is. The discriminator is the vendor's own not-found code."""
        blocker = FakeDeviceBlocker(
            unknown_macs={LAPTOP_MAC}, refused_macs={TABLET_MAC}
        )
        fx = _build(macs=(LAPTOP_MAC, TABLET_MAC), blocker=blocker)

        rule = await _block(fx)

        by_mac = {b.mac_address: b for b in rule.controller_blocks}
        assert by_mac[LAPTOP_MAC].error_code == CLIENT_NOT_FOUND
        assert by_mac[TABLET_MAC].error_code != CLIENT_NOT_FOUND
        assert by_mac[TABLET_MAC].status != by_mac[LAPTOP_MAC].status

    async def test_the_rules_own_status_still_answers_about_sessions_only(
        self,
    ) -> None:
        """``enforcement_status`` is the ladder the dashboard already reads
        (``src/lib/block-outcome.ts``) and what it means is "what happened
        to the sessions this guest was in" -- the promise the Blocked Guests
        form actually makes.

        A refused *device* block must not turn that into ``failed``, or an
        owner reads "we could not take them off the WiFi" about a guest who
        was taken off the WiFi. The device answers travel beside it.
        """
        blocker = FakeDeviceBlocker(refused_macs={PHONE_MAC})
        fx = _build(blocker=blocker)

        rule = await _block(fx)

        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert rule.sessions_ended == 1
        assert fx.adapter.active_users == set()
        assert rule.controller_blocks[0].status == BlockEnforcementStatus.FAILED.value

    async def test_retrying_supersedes_the_row_instead_of_adding_one(
        self,
    ) -> None:
        """``enforce_guest_rule`` is the retry an operator reaches for when
        the controller was unreachable, and it re-runs the whole
        enforcement. One row per (rule, venue, device), or a release later
        asks the same controller to unblock the same MAC once per click and
        the console shows one device four times.
        """
        blocker = FakeDeviceBlocker(refused_macs={PHONE_MAC})
        fx = _build(blocker=blocker)
        rule = await _block(fx)
        assert rule.controller_blocks[0].status == BlockEnforcementStatus.FAILED.value

        blocker.refused_macs.clear()
        await fx.service.enforce_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert len(fx.repository.controller_blocks) == 1
        assert (
            fx.repository.controller_blocks[0].status
            == BlockEnforcementStatus.ENFORCED.value
        )

    async def test_only_a_confirmed_block_records_a_blocked_at(self) -> None:
        """Never on a guess -- the same rule the rule row already follows."""
        blocker = FakeDeviceBlocker(
            unknown_macs={LAPTOP_MAC}, refused_macs={TABLET_MAC}
        )
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC, TABLET_MAC), blocker=blocker)

        rule = await _block(fx)

        by_mac = {b.mac_address: b for b in rule.controller_blocks}
        assert by_mac[PHONE_MAC].blocked_at is not None
        assert by_mac[LAPTOP_MAC].blocked_at is None
        assert by_mac[TABLET_MAC].blocked_at is None


# ============================================================================
# A legacy venue cannot block at all, and is told so
# ============================================================================


class TestLegacyVenuesAreRefusedWithTheReason:
    async def test_a_hotspot_operator_venue_records_unenforced_with_the_reason(
        self,
    ) -> None:
        """A venue connected with a hotspot-operator login cannot block per
        client at all -- the capability needs admin or Open API credentials.

        Gated on the provider's own declared capability, with the provider's
        own sentence, and with **no fallback**: there is no second mechanism
        to reach for, and inventing one would put a green tick on a venue
        where nothing happened.
        """
        blocker = FakeDeviceBlocker(unsupported_reason="Needs Open API credentials.")
        fx = _build(blocker=blocker)

        rule = await _block(fx)

        assert blocker.blocked == []
        recorded = rule.controller_blocks[0]
        assert recorded.status == BlockEnforcementStatus.UNENFORCED.value
        assert recorded.error_message == "Needs Open API credentials."

    async def test_a_refusal_is_not_releasable_because_nothing_was_placed(
        self,
    ) -> None:
        """The line ``list_open_controller_blocks`` draws. Asking a
        controller to unblock a MAC it never blocked is a write with no
        subject, and a row that claims a release happened is the same class
        of lie as a block that never landed."""
        blocker = FakeDeviceBlocker(unsupported_reason="Needs Open API credentials.")
        fx = _build(blocker=blocker)
        rule = await _block(fx)

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert blocker.released == []


# ============================================================================
# Which venues, resolved from the rule alone
# ============================================================================


class TestVenueScope:
    async def test_a_venue_scoped_rule_blocks_at_that_venue(self) -> None:
        fx = _build()

        rule = await _block(fx)

        assert fx.blocker.blocked == [(fx.location_id, PHONE_MAC)]
        assert rule.controller_blocks[0].location_id == fx.location_id

    async def test_an_org_wide_rule_uses_the_venues_the_guest_was_on(
        self,
    ) -> None:
        """An organization-wide rule names no venue of its own, and a
        controller block is per-site -- so the venues are the ones the
        guest's live sessions were on, resolved under the same organization.
        Guessing a venue would be writing a block into somebody else's
        site."""
        fx = _build()

        await _block(fx, location_id=None)

        assert fx.blocker.blocked == [(fx.location_id, PHONE_MAC)]

    async def test_an_org_wide_rule_for_an_offline_guest_blocks_nothing(
        self,
    ) -> None:
        """No venue this platform can name. It says so by doing nothing,
        rather than by fanning the block out across every venue the tenant
        owns."""
        fx = _build(online=False)

        await _block(fx, location_id=None)

        assert fx.blocker.presence_checks == []
        assert fx.blocker.blocked == []

    async def test_no_customer_input_ever_names_the_venue(self) -> None:
        """Tenancy. The location written to comes from the rule's own row,
        never from anything the caller supplied beyond it -- and a location
        the rule does not name is never touched."""
        fx = _build()

        await _block(fx)

        assert fx.other_location_id not in {loc for loc, _ in fx.blocker.blocked}
        assert fx.other_location_id not in fx.blocker.presence_checks


# ============================================================================
# Unblock finds what the block wrote
# ============================================================================


class TestReleaseUsesWhatWasPersisted:
    async def test_deactivating_releases_every_block_that_was_placed(
        self,
    ) -> None:
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC))
        rule = await _block(fx)

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert [mac for _, mac in fx.blocker.released] == [PHONE_MAC, LAPTOP_MAC]
        assert all(b.cleared_at is not None for b in fx.repository.controller_blocks)

    async def test_deleting_releases_before_the_rule_goes_away(self) -> None:
        """The open blocks are found by ``rule_id``. A release attempted
        after the rule had been removed is a release nobody could start."""
        fx = _build()
        rule = await _block(fx)

        await fx.service.delete_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert [mac for _, mac in fx.blocker.released] == [PHONE_MAC]

    async def test_a_device_the_guest_no_longer_owns_is_still_released(
        self,
    ) -> None:
        """**The test that proves the persistence is load-bearing.**

        The release reads the stored rows, not the guest's current devices.
        Re-deriving it would miss a device the guest has since replaced --
        and there is no readable list of blocked clients through the
        connection this platform holds (measured, CAPABILITY-MATRIX §4.4),
        so that device would stay blocked on the customer's own network with
        nothing left anywhere pointing at it.
        """
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC))
        rule = await _block(fx)
        # The guest replaces their laptop: the device table no longer
        # associates that MAC with them at all.
        fx.session_lookup.guest_devices = {
            fx.guest_id: [FakeDevice(mac_address=PHONE_MAC)]
        }

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert LAPTOP_MAC in {mac for _, mac in fx.blocker.released}

    async def test_a_release_that_did_not_land_leaves_the_row_open(self) -> None:
        """Uncleared on purpose. That row is what the expiry sweep comes
        back for, and it is the only reason a controller that was down at
        the moment of the unblock does not become a permanently blocked
        customer device."""
        blocker = FakeDeviceBlocker(release_failures={PHONE_MAC})
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC), blocker=blocker)
        rule = await _block(fx)

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        by_mac = {b.mac_address: b for b in fx.repository.controller_blocks}
        assert by_mac[PHONE_MAC].cleared_at is None
        assert by_mac[PHONE_MAC].release_error == "The controller did not answer."
        assert by_mac[LAPTOP_MAC].cleared_at is not None

    async def test_a_failed_release_stays_in_the_set_a_retry_reads(self) -> None:
        """Idempotent on the controller (a second unblock returns
        ``errorCode 0``, CAPABILITY-MATRIX §4.2), so retrying is free and
        the row staying open is what makes the retry possible at all."""
        blocker = FakeDeviceBlocker(release_failures={PHONE_MAC})
        fx = _build(blocker=blocker)
        rule = await _block(fx)
        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        still_open = await fx.repository.list_open_controller_blocks(rule_id=rule.id)

        assert [b.mac_address for b in still_open] == [PHONE_MAC]

    async def test_releasing_with_no_blocker_never_claims_a_release(self) -> None:
        """A process with no controller connection wired must leave every
        row exactly as it found it. Reporting a release nobody performed is
        how a device is stranded with a row saying it is free."""
        enforcer = BlocklistEnforcer(
            session_lookup=object(),
            router_lookup=object(),
            terminated_session_status=TERMINATED,
        )

        results = await enforcer.release_devices(
            [
                _StoredBlock(
                    organization_id=uuid.uuid4(),
                    location_id=uuid.uuid4(),
                    mac_address=PHONE_MAC,
                )
            ]
        )

        assert [outcome.released for _, outcome in results] == [False]
        assert results[0][1].error_message is not None


@dataclass
class _StoredBlock:
    organization_id: uuid.UUID
    location_id: uuid.UUID
    mac_address: str


# ============================================================================
# MikroTik
# ============================================================================


class TestMikroTikIsUntouched:
    async def test_a_router_api_venue_is_never_written_to(self) -> None:
        """One indexed question, answered "no", and the path stops.

        No device lookup, no controller call, no stored row. The RouterOS
        block is what it was: remove the guest from ``/ip hotspot active``
        and move the session row. No address list, no ip-binding, no filter
        rule -- which is also why unblocking a RouterOS venue still needs no
        device work at all.
        """
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC), controller_venue=False)

        rule = await _block(fx)

        assert fx.blocker.presence_checks == [fx.location_id]
        assert fx.blocker.blocked == []
        assert fx.session_lookup.device_lookups == []
        assert fx.repository.controller_blocks == []
        assert rule.controller_blocks == []

    async def test_the_session_is_still_ended_exactly_as_before(self) -> None:
        """The half that must not regress: the guest comes off the router's
        own active table and the session row moves to a terminal status."""
        fx = _build(controller_venue=False)

        rule = await _block(fx)

        assert fx.adapter.active_users == set()
        assert fx.adapter.active_macs == set()
        assert fx.session_lookup.sessions[fx.guest_id][0].status == TERMINATED
        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert rule.sessions_ended == 1

    async def test_unblocking_a_router_api_venue_contacts_nothing(self) -> None:
        fx = _build(controller_venue=False)
        rule = await _block(fx)

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert fx.blocker.released == []
        assert len(fx.adapter.calls) == 1


# ============================================================================
# The wiring, constructed the way the app constructs it
# ============================================================================


class TestTheWiringIsReal:
    """A factory nobody instantiates in a test is how three "shipped"
    features turned out never to run, and how the disconnect that reached
    every Omada venue sent a phone number where a MAC belongs. So the real
    factories are called here, with the arguments the app passes.
    """

    def test_get_block_enforcer_wires_a_device_blocker(self) -> None:
        from app.domains.guest_access.dependencies import get_block_enforcer

        enforcer = get_block_enforcer(db=object(), router_service=object())

        assert enforcer.device_blocker is not None

    def test_the_blocker_the_app_builds_answers_the_protocol(self) -> None:
        """Constructing is not enough -- the object has to have the three
        methods the enforcer calls, with the names it calls them by. A hook
        that constructs and then does not answer is the failure this class
        exists for."""
        from app.domains.network_integration.client_hooks import (
            build_controller_device_blocker,
        )

        blocker = build_controller_device_blocker(object())

        assert callable(blocker.controller_present)
        assert callable(blocker.block_device)
        assert callable(blocker.release_device)

    def test_the_release_sweep_is_registered_and_scheduled(self) -> None:
        """The sweep is the only thing standing between a time-bound block
        and a permanently blocked device, and a task that is written but
        never scheduled does nothing at all -- which is indistinguishable,
        from the outside, from not having written it."""
        from app.core.celery_app import celery_app
        from app.domains.guest_access.constants import (
            TASK_RUN_CONTROLLER_BLOCK_RELEASE_SWEEP,
        )
        from app.domains.guest_access.tasks import (  # noqa: F401
            run_controller_block_release_sweep,
        )

        assert TASK_RUN_CONTROLLER_BLOCK_RELEASE_SWEEP in celery_app.tasks
        scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
        assert TASK_RUN_CONTROLLER_BLOCK_RELEASE_SWEEP in scheduled

    def test_the_sweep_builds_the_same_enforcer_shape_as_a_request(self) -> None:
        """An enforcer assembled differently on the schedule than in the API
        is how a capability comes to work when a human clicks it and do
        nothing when nobody does."""
        import inspect

        from app.domains.guest_access import tasks

        source = inspect.getsource(tasks._run_controller_block_release_async)
        assert "device_blocker=build_controller_device_blocker(session)" in source


# ============================================================================
# The hook itself, against the provider seam
# ============================================================================


class TestTheControllerHookTranslatesTheVendorHonestly:
    """``client_hooks._client_block_action`` is where a vendor error becomes
    one of the four outcomes. Driven here with a real provider double
    through the real seam, because the mapping is the part that decides
    whether an operator is told something true."""

    @staticmethod
    def _resolved(auth_mode: str, provider):  # noqa: ANN001, ANN205
        from app.domains.network_integration.client_hooks import _ResolvedController
        from app.domains.network_integration.providers.base import (
            ProviderConnectionConfig,
        )

        from .test_network_integration import _integration

        integration = _integration(auth_mode=auth_mode)
        return _ResolvedController(
            integration=integration,
            provider=provider,
            config=ProviderConnectionConfig(
                provider="omada",
                base_url="https://controller.example.com:8043",
                auth_mode=auth_mode,
                credentials={},
                controller_id="cid",
                tls_mode="system",
                tls_pinned_sha256=None,
                timeout_seconds=5.0,
            ),
            site_id="site-1",
        )

    async def _act(self, monkeypatch, resolved, *, action="block"):  # noqa: ANN001, ANN202
        from app.domains.network_integration import client_hooks

        async def _fake_resolve(*_args: object, **_kwargs: object):
            return resolved

        monkeypatch.setattr(client_hooks, "_resolve", _fake_resolve)
        return await client_hooks._client_block_action(
            None,
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            client_mac=PHONE_MAC,
            action=action,
        )

    async def test_a_client_the_controller_does_not_know_is_not_a_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.domains.network_integration.exceptions import (
            ProviderClientNotFoundError,
        )

        from .test_network_integration import FakeProvider

        provider = FakeProvider()
        provider.raise_on["block_client"] = ProviderClientNotFoundError()

        outcome = await self._act(monkeypatch, self._resolved("openapi", provider))

        assert outcome.status == BlockEnforcementStatus.NOT_APPLICABLE.value
        assert outcome.error_code == CLIENT_NOT_FOUND

    async def test_a_refusal_is_a_failure_and_carries_its_own_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.domains.network_integration.exceptions import (
            ProviderConnectionFailedError,
        )

        from .test_network_integration import FakeProvider

        provider = FakeProvider()
        provider.raise_on["block_client"] = ProviderConnectionFailedError()

        outcome = await self._act(monkeypatch, self._resolved("openapi", provider))

        assert outcome.status == BlockEnforcementStatus.FAILED.value
        assert outcome.error_code != CLIENT_NOT_FOUND

    async def test_a_legacy_venue_is_refused_before_anything_is_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Gated on the declared capability, so the venue gets a sentence
        naming what would be needed instead of a controller error that reads
        like a network fault. Nothing is sent, which is the part that
        matters: there is no fallback path."""
        from .test_network_integration import FakeProvider

        provider = FakeProvider()

        outcome = await self._act(monkeypatch, self._resolved("legacy", provider))

        assert outcome.status == BlockEnforcementStatus.UNENFORCED.value
        assert outcome.error_message
        assert provider.client_actions == []

    async def test_a_confirmed_block_is_the_only_thing_that_reads_enforced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from .test_network_integration import FakeProvider

        provider = FakeProvider()

        outcome = await self._act(monkeypatch, self._resolved("openapi", provider))

        assert outcome.status == BlockEnforcementStatus.ENFORCED.value
        assert [call[0] for call in provider.client_actions] == ["block_client"]

    async def test_a_release_of_an_unknown_client_counts_as_released(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing left to do is the state the caller wanted, and saying so
        is not the same as claiming a write landed. Anything else leaves the
        row open."""
        from app.domains.network_integration import client_hooks
        from app.domains.network_integration.exceptions import (
            ProviderClientNotFoundError,
        )

        from .test_network_integration import FakeProvider

        provider = FakeProvider()
        provider.raise_on["unblock_client"] = ProviderClientNotFoundError()
        resolved = self._resolved("openapi", provider)

        async def _fake_resolve(*_args: object, **_kwargs: object):
            return resolved

        monkeypatch.setattr(client_hooks, "_resolve", _fake_resolve)
        blocker = client_hooks.build_controller_device_blocker(None)

        outcome = await blocker.release_device(
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            client_mac=PHONE_MAC,
        )

        assert outcome.released is True

    async def test_a_venue_with_no_controller_is_reported_unenforced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not a failure and not a success -- "nobody was there to do it",
        which is the value ``UNENFORCED`` already means."""
        outcome = await self._act(monkeypatch, None)

        assert outcome.status == BlockEnforcementStatus.UNENFORCED.value


# ============================================================================
# What is deliberately not claimed
# ============================================================================


class TestNothingOverclaims:
    async def test_a_block_is_recorded_without_any_claim_about_live_sessions(
        self,
    ) -> None:
        """What a controller block does to a guest holding a live portal
        authorization is UNMEASURED (CAPABILITY-MATRIX §4.6). The session
        ending is a separate mechanism with its own counter, and a stored
        block never contributes to it.
        """
        fx = _build(macs=(PHONE_MAC, LAPTOP_MAC, TABLET_MAC))

        rule = await _block(fx)

        assert rule.sessions_ended == 1
        assert len(rule.controller_blocks) == 3

    async def test_the_platform_rule_is_what_refuses_the_person(self) -> None:
        """The vendor-side block is a deterrent keyed on a MAC. The rule is
        what actually refuses them, it is vendor-neutral, and it is in force
        whether or not a single controller write succeeded."""
        blocker = FakeDeviceBlocker(refused_macs={PHONE_MAC})
        fx = _build(blocker=blocker)
        rule = await _block(fx)

        matching = [rule]

        async def _list_matching(**_: object) -> list[GuestAccessRule]:
            return [r for r in matching if r.is_active]

        async def _no_device_rules(**_: object) -> list[object]:
            return []

        fx.repository.list_matching_guest_rules = _list_matching  # type: ignore[attr-defined]
        fx.repository.list_matching_device_rules = _no_device_rules  # type: ignore[attr-defined]

        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier=IDENTIFIER,
            mac_address=None,
        )

        assert decision.allowed is False
        assert rule.controller_blocks[0].status == BlockEnforcementStatus.FAILED.value

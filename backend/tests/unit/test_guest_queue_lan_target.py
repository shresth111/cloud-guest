"""A per-guest ``/queue simple`` is only ever written against an address
that can be the guest's own.

The defect this pins, as observed on a live RouterOS venue: a guest who
opened the portal without being redirected by the hotspot (the device was
already let through) signed in, the login endpoint recorded
``payload.ip_address or request.client.host`` -- the second half, i.e. the
venue's public WAN address -- and a queue was created on the router with
that address as its target. It read back, it showed ACTIVE, and it matched
no packet: the venue's saved speed limit applied to nobody.

Three layers are covered, outermost first:

* ``validators.routeros_guest_queue_target`` -- the pure rule.
* ``GuestService._queue_device_target`` -- a login with an unusable address
  dispatches nothing at all.
* ``QueueManagementService`` -- a policy re-apply or an admin's own request
  cannot write one either, and refusing never disturbs the row that is
  correctly limiting the address's real holder.

Uses the fakes from ``test_queue_management`` unchanged. Nothing here talks
to a device; whether RouterOS matches a correctly targeted queue for a
hotspot-bypassed host is a hardware question these tests do not answer.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.guest.service import GuestService
from app.domains.queue_management.constants import QueueStatus, QueueTargetType
from app.domains.queue_management.exceptions import QueueTargetNotLanAddressError
from app.domains.queue_management.validators import routeros_guest_queue_target
from tests.unit.test_queue_management import (
    Harness,
    _make_router,
    _seed_assignment,
    make_harness,
)

# Documentation ranges only (RFC 5737) -- never a real venue's address.
PUBLIC_ADDRESS = "203.0.113.24"
LAN_ADDRESS = "10.5.50.254"


class TestRouterosGuestQueueTarget:
    @pytest.mark.parametrize(
        "address",
        ["10.5.50.254", "172.16.4.9", "192.168.88.20", " 10.5.50.7 ", "10.5.50.7/32"],
    )
    def test_an_rfc1918_address_is_a_target(self, address: str) -> None:
        assert routeros_guest_queue_target(address) == address.strip()

    @pytest.mark.parametrize(
        "address",
        [
            None,
            "",
            PUBLIC_ADDRESS,  # what the internet saw
            f"{PUBLIC_ADDRESS}/32",
            "100.64.3.2",  # carrier-grade NAT: an ISP's side, not the LAN's
            "127.0.0.1",
            "169.254.10.10",
            "0.0.0.0",
            "2001:db8::1",
            "not-an-address",
            "AA:BB:CC:DD:EE:FF",  # a MAC matches nothing in /queue simple
            "10.5.50.0/24",  # one guest, one address: never a whole subnet
        ],
    )
    def test_anything_else_is_not(self, address: str | None) -> None:
        assert routeros_guest_queue_target(address) is None

    def test_the_routers_own_addresses_are_not_a_guest(self) -> None:
        assert (
            routeros_guest_queue_target(
                "10.20.0.31", router_addresses=("10.20.0.31", None)
            )
            is None
        )
        assert (
            routeros_guest_queue_target(
                "10.5.50.2", router_addresses=("10.20.0.31", "", "garbage")
            )
            == "10.5.50.2"
        )


class TestLoginDispatchesNoQueueForAnUnusableAddress:
    """``_queue_device_target`` is what every login method asks before it
    enqueues anything; ``None`` means nothing is enqueued."""

    async def _target(self, ip_address: str | None) -> str | None:
        router = _make_router()
        session = SimpleNamespace(
            id=uuid.uuid4(), ip_address=ip_address, device_id=None
        )
        # No repository is touched on the RouterOS branch, so the unbound
        # method is exercised against a bare stand-in for ``self``.
        return await GuestService._queue_device_target(
            SimpleNamespace(), session=session, router=router
        )

    async def test_the_hotspot_supplied_lan_address_is_used(self) -> None:
        assert await self._target(LAN_ADDRESS) == LAN_ADDRESS

    async def test_the_request_source_address_is_not(self) -> None:
        assert await self._target(PUBLIC_ADDRESS) is None

    async def test_no_address_at_all_is_not(self) -> None:
        assert await self._target(None) is None

    async def test_the_refusal_is_logged_not_silent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            await self._target(PUBLIC_ADDRESS)
        records = [
            r for r in caplog.records if r.msg == "guest_queue_target_not_lan_address"
        ]
        assert len(records) == 1
        assert records[0].speed_limit_applied is False
        # The address itself stays out of the log line.
        assert PUBLIC_ADDRESS not in caplog.text


async def _resolve(h: Harness, router, *, target_id: uuid.UUID, address: str):
    return await h.service.resolve_and_assign_queue(
        requesting_organization_id=router.organization_id,
        location_id=router.location_id,
        router_id=router.id,
        target_type=QueueTargetType.SESSION,
        target_id=target_id,
        device_target=address,
    )


class TestQueueServiceRefusesANonLanSessionTarget:
    async def test_resolve_writes_nothing_for_a_public_address(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        with pytest.raises(QueueTargetNotLanAddressError):
            await _resolve(h, router, target_id=uuid.uuid4(), address=PUBLIC_ADDRESS)

        assert h.device_adapter.created_calls == []
        assert h.repository.assignments == {}

    async def test_an_empty_target_is_refused_too(self) -> None:
        """An empty RouterOS ``target`` is not "no target" -- it is every
        address, i.e. one guest's rate applied to the whole venue."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        with pytest.raises(QueueTargetNotLanAddressError):
            await _resolve(h, router, target_id=uuid.uuid4(), address="")

        assert h.device_adapter.created_calls == []

    async def test_a_refusal_does_not_retire_the_addresss_real_holder(self) -> None:
        """The refusal comes before the supersede pass. Otherwise a login
        carrying the wrong address would pull the queue off whoever
        correctly holds... nothing, in this case -- but the ordering is the
        guarantee, so it is pinned with a live row on the router."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        first = await _resolve(h, router, target_id=uuid.uuid4(), address=LAN_ADDRESS)

        with pytest.raises(QueueTargetNotLanAddressError):
            await _resolve(h, router, target_id=uuid.uuid4(), address=PUBLIC_ADDRESS)

        assert h.device_adapter.removed_ids == []
        assert h.repository.assignments[first.id].status == QueueStatus.ACTIVE.value
        assert [c["target"] for c in h.device_adapter.created_calls] == [LAN_ADDRESS]

    async def test_a_lan_address_is_applied_as_before(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        assignment = await _resolve(
            h, router, target_id=uuid.uuid4(), address=LAN_ADDRESS
        )

        assert assignment.status == QueueStatus.ACTIVE.value
        assert [c["target"] for c in h.device_adapter.created_calls] == [LAN_ADDRESS]

    async def test_apply_refuses_a_row_that_already_names_a_public_address(
        self,
    ) -> None:
        """Rows written before this gate existed, or created through the
        admin API, reach ``apply_queue`` directly."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=None,
            name="System 30720k/30720k",
            download_rate_kbps=30720,
            upload_rate_kbps=30720,
            is_system_profile=True,
        )
        row = _seed_assignment(
            h,
            router=router,
            target_id=uuid.uuid4(),
            device_target=PUBLIC_ADDRESS,
            queue_profile_id=profile.id,
            status=QueueStatus.PENDING.value,
        )

        with pytest.raises(QueueTargetNotLanAddressError) as raised:
            await h.service.apply_queue(
                row.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert h.device_adapter.created_calls == []
        stored = h.repository.assignments[row.id]
        assert stored.status == QueueStatus.PENDING.value
        assert stored.error_message == str(raised.value)
        # Stored on the row and returned to API callers: no address in it.
        assert PUBLIC_ADDRESS not in str(raised.value)

    async def test_a_policy_reapply_does_not_recreate_a_public_address_row(
        self,
    ) -> None:
        """The row already on a router from before this fix: ACTIVE, public
        target, inert. A bandwidth publish must count it as failed rather
        than move it to a fresh, equally inert row."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        old_profile = await h.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=None,
            name="System 30720k/30720k",
            download_rate_kbps=30720,
            upload_rate_kbps=30720,
            is_system_profile=True,
        )
        legacy = _seed_assignment(
            h,
            router=router,
            target_id=uuid.uuid4(),
            device_target=PUBLIC_ADDRESS,
            queue_profile_id=old_profile.id,
            device_queue_id="*2",
        )
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": 10240,
            "upload_rate_kbps": 10240,
            "burst_download_kbps": None,
            "burst_upload_kbps": None,
            "burst_threshold_kbps": None,
            "burst_time_seconds": None,
            "priority": None,
        }

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 0, "failed": 1}
        assert h.device_adapter.created_calls == []
        assert list(h.repository.assignments) == [legacy.id]

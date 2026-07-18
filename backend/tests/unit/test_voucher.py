"""Unit tests for the Voucher domain (BE-010 Part 2): batch lifecycle
(draft -> pending_approval -> approved -> active, revoke, the
``voucher.manage`` fast-path bypass), bulk code generation (uniqueness,
print-friendly alphabet, bulk-size handling), validate vs redeem semantics,
single-use vs multi-use redemption, expiry (both batch-level and
post-redemption), export CSV correctness, import behavior, redemption rate
limiting, and tenant isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_otp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``VoucherService`` is exercised against small, hand-rolled
in-memory fakes for its repository, Redis client, audit writer, and
organization/location lookups (mirroring ``test_router_provisioning.py``'s
own ``FakeOrganizationLookup``/``FakeLocationLookup`` shape) -- there is no
live Postgres/Redis in this environment.
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.constants import MAX_BULK_CREATE_SIZE, SortOrder
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.voucher.constants import (
    MAX_CODE_LENGTH,
    MIN_CODE_LENGTH,
    VOUCHER_CODE_ALPHABET,
    VoucherBatchStatus,
    VoucherStatus,
)
from app.domains.voucher.exceptions import (
    CrossOrganizationVoucherBatchAccessError,
    InvalidBatchStatusTransitionError,
    InvalidCodeLengthError,
    VoucherBatchNotActiveError,
    VoucherBatchNotFoundError,
    VoucherBatchQuantityExceededError,
    VoucherExhaustedError,
    VoucherExpiredError,
    VoucherNotFoundError,
    VoucherRedemptionRateLimitExceededError,
    VoucherRevokedError,
)
from app.domains.voucher.models import Voucher, VoucherBatch
from app.domains.voucher.service import VoucherRedemptionRateLimiter, VoucherService

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationLookup:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(self) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status="active",
                parent_organization_id=None,
                contact_email="admin@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        return organization


@dataclass
class FakeLocationLookup:
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None or (location.is_deleted and not include_deleted):
            raise LocationNotFoundError(location_id)
        if (
            requesting_organization_id is not None
            and location.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationLocationAccessError()
        return location

    def add(self, *, organization_id: uuid.UUID) -> Location:
        location = Location(
            **_base_fields(
                organization_id=organization_id,
                name="HQ",
                slug=f"hq-{uuid.uuid4()}",
                status="active",
                address_line1="1 Main St",
                address_line2=None,
                city="Austin",
                state_province="TX",
                postal_code="78701",
                country="US",
                timezone="UTC",
                latitude=None,
                longitude=None,
                contact_name=None,
                contact_phone=None,
                contact_email=None,
                settings={},
            )
        )
        self.locations[location.id] = location
        return location


@dataclass
class FakeVoucherRepository:
    batches: dict[uuid.UUID, VoucherBatch] = field(default_factory=dict)
    vouchers: dict[uuid.UUID, Voucher] = field(default_factory=dict)

    # -- batches -------------------------------------------------------------

    async def create_batch(self, **fields: object) -> VoucherBatch:
        batch = VoucherBatch(**_base_fields(**fields))
        self.batches[batch.id] = batch
        return batch

    async def get_batch(self, batch_id: uuid.UUID) -> VoucherBatch | None:
        return self.batches.get(batch_id)

    async def update_batch(
        self, batch: VoucherBatch, data: dict[str, object]
    ) -> VoucherBatch:
        for key, value in data.items():
            setattr(batch, key, value)
        batch.version += 1
        return batch

    async def list_batches(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherBatch], PaginationMeta]:
        items = list(self.batches.values())
        for key, value in (filters or {}).items():
            items = [item for item in items if getattr(item, key) == value]
        items.sort(
            key=lambda item: getattr(item, sort_by),
            reverse=(sort_order == SortOrder.DESC),
        )
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    # -- vouchers --------------------------------------------------------------

    async def bulk_create_vouchers(
        self, items: list[dict[str, object]]
    ) -> list[Voucher]:
        created = []
        for item in items:
            voucher = Voucher(**_base_fields(**item))
            self.vouchers[voucher.id] = voucher
            created.append(voucher)
        return created

    async def get_voucher_by_code(self, code: str) -> Voucher | None:
        return next((v for v in self.vouchers.values() if v.code == code), None)

    async def find_existing_codes(self, codes: list[str]) -> list[str]:
        code_set = set(codes)
        return [v.code for v in self.vouchers.values() if v.code in code_set]

    async def update_voucher(
        self, voucher: Voucher, data: dict[str, object]
    ) -> Voucher:
        for key, value in data.items():
            setattr(voucher, key, value)
        voucher.version += 1
        return voucher

    async def list_vouchers_for_batch(
        self, batch_id: uuid.UUID, *, page: int, page_size: int
    ) -> tuple[list[Voucher], PaginationMeta]:
        items = [v for v in self.vouchers.values() if v.batch_id == batch_id]
        items.sort(key=lambda item: item.created_at)
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    async def list_all_vouchers_for_batch(self, batch_id: uuid.UUID) -> list[Voucher]:
        items = [v for v in self.vouchers.values() if v.batch_id == batch_id]
        items.sort(key=lambda item: item.created_at)
        return items

    async def get_batch_status_counts(self, batch_id: uuid.UUID) -> dict[str, int]:
        counts: dict[str, int] = {}
        for voucher in self.vouchers.values():
            if voucher.batch_id != batch_id:
                continue
            counts[voucher.status] = counts.get(voucher.status, 0) + 1
        return counts

    async def bulk_revoke_vouchers_for_batch(self, batch_id: uuid.UUID) -> int:
        terminal = {
            VoucherStatus.EXHAUSTED.value,
            VoucherStatus.EXPIRED.value,
            VoucherStatus.REVOKED.value,
        }
        count = 0
        for voucher in self.vouchers.values():
            if voucher.batch_id == batch_id and voucher.status not in terminal:
                voucher.status = VoucherStatus.REVOKED.value
                count += 1
        return count


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis`` --
    mirrors ``tests/unit/test_otp.py``'s own ``FakeRedis``."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)


@dataclass
class Fixture:
    repository: FakeVoucherRepository
    redis: FakeRedis
    audit_writer: FakeAuditLogWriter
    organization_lookup: FakeOrganizationLookup
    location_lookup: FakeLocationLookup
    service: VoucherService
    organization: Organization


def make_service(
    *, redemption_max_attempts_per_window: int = 30, redemption_window_minutes: int = 1
) -> Fixture:
    repository = FakeVoucherRepository()
    redis = FakeRedis()
    audit_writer = FakeAuditLogWriter()
    organization_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    organization = organization_lookup.add()
    service = VoucherService(
        repository,
        redis,
        organization_lookup,
        location_lookup,
        audit_writer=audit_writer,
        redemption_max_attempts_per_window=redemption_max_attempts_per_window,
        redemption_window_minutes=redemption_window_minutes,
    )
    return Fixture(
        repository=repository,
        redis=redis,
        audit_writer=audit_writer,
        organization_lookup=organization_lookup,
        location_lookup=location_lookup,
        service=service,
        organization=organization,
    )


async def _create_batch(
    fx: Fixture,
    *,
    quantity: int = 5,
    code_length: int = 8,
    code_prefix: str | None = None,
    validity_minutes: int = 60,
    batch_expires_at: datetime | None = None,
    max_uses_per_voucher: int = 1,
    has_manage_permission: bool = False,
) -> VoucherBatch:
    return await fx.service.create_batch(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=fx.organization.id,
        organization_id=fx.organization.id,
        location_id=None,
        name="Test Batch",
        quantity=quantity,
        code_length=code_length,
        code_prefix=code_prefix,
        validity_minutes=validity_minutes,
        batch_expires_at=batch_expires_at,
        max_uses_per_voucher=max_uses_per_voucher,
        data_limit_mb=None,
        notes=None,
        has_manage_permission=has_manage_permission,
    )


# ============================================================================
# Batch lifecycle
# ============================================================================


class TestBatchLifecycle:
    async def test_create_batch_auto_submits_to_pending_approval(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        assert batch.status == VoucherBatchStatus.PENDING_APPROVAL.value

    async def test_approve_batch_moves_to_active(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        approved = await fx.service.approve_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        assert approved.status == VoucherBatchStatus.ACTIVE.value
        assert approved.approved_by_user_id is not None
        assert approved.approved_at is not None

    async def test_approve_writes_both_approved_and_activated_audit_entries(
        self,
    ) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        await fx.service.approve_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert "voucher_batch_created" in actions
        assert "voucher_batch_approved" in actions
        assert "voucher_batch_activated" in actions

    async def test_manage_permission_bypasses_approval_queue(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, has_manage_permission=True)
        assert batch.status == VoucherBatchStatus.ACTIVE.value
        assert batch.approved_by_user_id is not None

    async def test_revoke_batch_from_active(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, has_manage_permission=True)
        revoked = await fx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        assert revoked.status == VoucherBatchStatus.REVOKED.value

    async def test_revoke_cascades_to_unused_vouchers(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=3, has_manage_permission=True)
        await fx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        vouchers = [
            v for v in fx.repository.vouchers.values() if v.batch_id == batch.id
        ]
        assert all(v.status == VoucherStatus.REVOKED.value for v in vouchers)

    async def test_revoking_already_revoked_batch_raises(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, has_manage_permission=True)
        await fx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        with pytest.raises(InvalidBatchStatusTransitionError):
            await fx.service.revoke_batch(
                batch_id=batch.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=fx.organization.id,
            )

    async def test_approving_a_revoked_batch_raises(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        await fx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        with pytest.raises(InvalidBatchStatusTransitionError):
            await fx.service.approve_batch(
                batch_id=batch.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=fx.organization.id,
            )

    async def test_batch_not_found_raises(self) -> None:
        fx = make_service()
        with pytest.raises(VoucherBatchNotFoundError):
            await fx.service.get_batch(
                uuid.uuid4(), requesting_organization_id=fx.organization.id
            )

    async def test_batch_lazily_expires_on_read(self) -> None:
        fx = make_service()
        batch = await _create_batch(
            fx,
            has_manage_permission=True,
            batch_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        assert batch.status == VoucherBatchStatus.ACTIVE.value
        refreshed = await fx.service.get_batch(
            batch.id, requesting_organization_id=fx.organization.id
        )
        assert refreshed.status == VoucherBatchStatus.EXPIRED.value


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_cross_organization_get_raises(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        other_org = fx.organization_lookup.add()
        with pytest.raises(CrossOrganizationVoucherBatchAccessError):
            await fx.service.get_batch(
                batch.id, requesting_organization_id=other_org.id
            )

    async def test_create_batch_for_another_organization_raises(self) -> None:
        fx = make_service()
        other_org = fx.organization_lookup.add()
        with pytest.raises(CrossOrganizationVoucherBatchAccessError):
            await fx.service.create_batch(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=other_org.id,
                organization_id=fx.organization.id,
                location_id=None,
                name="Cross-tenant",
                quantity=1,
                code_length=8,
                code_prefix=None,
                validity_minutes=60,
                batch_expires_at=None,
                max_uses_per_voucher=1,
                data_limit_mb=None,
                notes=None,
                has_manage_permission=False,
            )

    async def test_location_must_belong_to_batch_organization(self) -> None:
        fx = make_service()
        other_org = fx.organization_lookup.add()
        foreign_location = fx.location_lookup.add(organization_id=other_org.id)
        with pytest.raises(CrossOrganizationLocationAccessError):
            await fx.service.create_batch(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=fx.organization.id,
                organization_id=fx.organization.id,
                location_id=foreign_location.id,
                name="Bad location",
                quantity=1,
                code_length=8,
                code_prefix=None,
                validity_minutes=60,
                batch_expires_at=None,
                max_uses_per_voucher=1,
                data_limit_mb=None,
                notes=None,
                has_manage_permission=False,
            )

    async def test_platform_level_caller_may_access_any_organization(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx)
        # requesting_organization_id=None means a platform-level caller.
        fetched = await fx.service.get_batch(batch.id, requesting_organization_id=None)
        assert fetched.id == batch.id


# ============================================================================
# Code generation
# ============================================================================


class TestCodeGeneration:
    async def test_generates_requested_quantity_of_unique_codes(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=25, has_manage_permission=True)
        vouchers = [
            v for v in fx.repository.vouchers.values() if v.batch_id == batch.id
        ]
        assert len(vouchers) == 25
        assert len({v.code for v in vouchers}) == 25

    async def test_codes_use_only_print_friendly_alphabet(self) -> None:
        fx = make_service()
        batch = await _create_batch(
            fx, quantity=10, code_length=8, has_manage_permission=True
        )
        vouchers = [
            v for v in fx.repository.vouchers.values() if v.batch_id == batch.id
        ]
        ambiguous = set("0O1I") - set(VOUCHER_CODE_ALPHABET)
        assert ambiguous == set("0O1I")  # confirms none of these are in the alphabet
        for voucher in vouchers:
            body = voucher.code
            assert len(body) == 8
            assert all(char in VOUCHER_CODE_ALPHABET for char in body)
            assert not any(char in ambiguous for char in body)

    async def test_code_prefix_is_applied(self) -> None:
        fx = make_service()
        batch = await _create_batch(
            fx,
            quantity=3,
            code_length=6,
            code_prefix="JULY-",
            has_manage_permission=True,
        )
        vouchers = [
            v for v in fx.repository.vouchers.values() if v.batch_id == batch.id
        ]
        for voucher in vouchers:
            assert voucher.code.startswith("JULY-")
            assert len(voucher.code) == len("JULY-") + 6

    async def test_quantity_exceeding_bulk_limit_rejected(self) -> None:
        fx = make_service()
        with pytest.raises(VoucherBatchQuantityExceededError):
            await _create_batch(fx, quantity=MAX_BULK_CREATE_SIZE + 1)

    async def test_zero_quantity_batch_creates_no_vouchers(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=0)
        vouchers = [
            v for v in fx.repository.vouchers.values() if v.batch_id == batch.id
        ]
        assert vouchers == []

    async def test_code_length_out_of_bounds_rejected(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidCodeLengthError):
            await _create_batch(fx, code_length=MIN_CODE_LENGTH - 1)
        with pytest.raises(InvalidCodeLengthError):
            await _create_batch(fx, code_length=MAX_CODE_LENGTH + 1)


# ============================================================================
# Validate vs redeem semantics
# ============================================================================


class TestValidateVsRedeem:
    async def test_validate_does_not_mutate_voucher(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        result = await fx.service.validate_voucher(code=voucher.code, source="1.2.3.4")
        assert result.is_first_use is True
        assert result.uses_remaining == 1
        refreshed = await fx.repository.get_voucher_by_code(voucher.code)
        assert refreshed.status == VoucherStatus.UNUSED.value
        assert refreshed.use_count == 0

    async def test_redeem_mutates_voucher(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        redeemed, redeemed_batch = await fx.service.redeem_voucher(
            code=voucher.code, identifier="+15551234567", source="1.2.3.4"
        )
        assert redeemed.use_count == 1
        assert redeemed.redeemed_at is not None
        assert redeemed.redeemed_identifier == "+15551234567"
        assert redeemed.expires_at is not None
        assert redeemed_batch.id == batch.id

    async def test_validate_unknown_code_raises_not_found(self) -> None:
        fx = make_service()
        with pytest.raises(VoucherNotFoundError):
            await fx.service.validate_voucher(code="DOESNOTEXIST", source="1.2.3.4")

    async def test_redeem_batch_not_yet_active_raises(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1)  # PENDING_APPROVAL, not active
        voucher = next(iter(fx.repository.vouchers.values()))
        with pytest.raises(VoucherBatchNotActiveError):
            await fx.service.redeem_voucher(
                code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
            )

    async def test_every_successful_redemption_is_audited(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert "voucher_redeemed" in actions


# ============================================================================
# Single-use vs multi-use redemption
# ============================================================================


class TestSingleVsMultiUse:
    async def test_single_use_voucher_exhausts_on_first_redemption(self) -> None:
        fx = make_service()
        await _create_batch(
            fx, quantity=1, max_uses_per_voucher=1, has_manage_permission=True
        )
        voucher = next(iter(fx.repository.vouchers.values()))
        redeemed, _ = await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        assert redeemed.status == VoucherStatus.EXHAUSTED.value
        with pytest.raises(VoucherExhaustedError):
            await fx.service.redeem_voucher(
                code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
            )

    async def test_multi_use_voucher_stays_active_until_max_uses(self) -> None:
        fx = make_service()
        await _create_batch(
            fx, quantity=1, max_uses_per_voucher=3, has_manage_permission=True
        )
        voucher = next(iter(fx.repository.vouchers.values()))

        first, _ = await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        assert first.status == VoucherStatus.ACTIVE.value
        assert first.use_count == 1
        first_expires_at = first.expires_at

        second, _ = await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        assert second.status == VoucherStatus.ACTIVE.value
        assert second.use_count == 2
        # expires_at is only set at first redemption, never recomputed.
        assert second.expires_at == first_expires_at

        third, _ = await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        assert third.status == VoucherStatus.EXHAUSTED.value
        assert third.use_count == 3

        with pytest.raises(VoucherExhaustedError):
            await fx.service.redeem_voucher(
                code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
            )

    async def test_expires_at_is_null_until_first_redemption(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        assert voucher.expires_at is None


# ============================================================================
# Expiry
# ============================================================================


class TestExpiry:
    async def test_batch_expiry_rejects_unused_voucher(self) -> None:
        """A batch past its own ``batch_expires_at`` is lazily flipped to
        ``EXPIRED`` on read (see ``VoucherService._refresh_batch_expiry``),
        which then surfaces as ``VoucherBatchNotActiveError`` -- see that
        exception's docstring for why this, not a dedicated expiry error, is
        the right shape for batch-level (as opposed to per-voucher
        post-redemption) expiry."""
        fx = make_service()
        batch = await _create_batch(
            fx,
            quantity=1,
            has_manage_permission=True,
            batch_expires_at=datetime.now(UTC) + timedelta(seconds=3600),
        )
        voucher = next(iter(fx.repository.vouchers.values()))
        # Force the batch's expiry into the past without waiting on the clock.
        batch.batch_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(VoucherBatchNotActiveError):
            await fx.service.redeem_voucher(
                code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
            )
        refreshed = await fx.repository.get_batch(batch.id)
        assert refreshed.status == VoucherBatchStatus.EXPIRED.value

    async def test_post_redemption_expiry_rejects_reuse(self) -> None:
        fx = make_service()
        await _create_batch(
            fx,
            quantity=1,
            max_uses_per_voucher=5,
            validity_minutes=60,
            has_manage_permission=True,
        )
        voucher = next(iter(fx.repository.vouchers.values()))
        redeemed, _ = await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        assert redeemed.status == VoucherStatus.ACTIVE.value
        # Force the voucher's own post-redemption expiry into the past.
        redeemed.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(VoucherExpiredError):
            await fx.service.redeem_voucher(
                code=redeemed.code, identifier="guest@example.com", source="1.2.3.4"
            )

    async def test_revoked_voucher_rejected(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        voucher.status = VoucherStatus.REVOKED.value
        with pytest.raises(VoucherRevokedError):
            await fx.service.redeem_voucher(
                code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
            )


# ============================================================================
# Export CSV
# ============================================================================


class TestExportCsv:
    async def test_export_produces_one_row_per_voucher_plus_header(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=3, has_manage_permission=True)
        csv_text = await fx.service.export_batch_csv(
            batch_id=batch.id, requesting_organization_id=fx.organization.id
        )
        rows = list(csv.reader(io.StringIO(csv_text)))
        assert rows[0] == [
            "code",
            "status",
            "use_count",
            "max_uses_per_voucher",
            "redeemed_at",
            "last_used_at",
            "expires_at",
            "redeemed_identifier",
        ]
        assert len(rows) == 4  # header + 3 vouchers

    async def test_export_reflects_redemption_state(self) -> None:
        fx = make_service()
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        await fx.service.redeem_voucher(
            code=voucher.code, identifier="guest@example.com", source="1.2.3.4"
        )
        csv_text = await fx.service.export_batch_csv(
            batch_id=voucher.batch_id, requesting_organization_id=fx.organization.id
        )
        rows = list(csv.reader(io.StringIO(csv_text)))
        data_row = rows[1]
        assert data_row[0] == voucher.code
        assert data_row[1] == VoucherStatus.EXHAUSTED.value
        assert data_row[7] == "guest@example.com"


# ============================================================================
# Import
# ============================================================================


class TestImport:
    async def test_import_inserts_new_pre_printed_codes(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=0, has_manage_permission=True)
        result = await fx.service.import_vouchers(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
            codes=["PRINT-001", "PRINT-002"],
        )
        assert len(result.imported) == 2
        assert result.rejected == []
        stored_codes = {v.code for v in fx.repository.vouchers.values()}
        assert {"PRINT-001", "PRINT-002"} <= stored_codes

    async def test_import_rejects_duplicate_within_request(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=0, has_manage_permission=True)
        result = await fx.service.import_vouchers(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
            codes=["DUPE-001", "DUPE-001"],
        )
        assert len(result.imported) == 1
        assert len(result.rejected) == 1
        assert result.rejected[0][0] == "DUPE-001"

    async def test_import_rejects_code_already_in_database(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=1, has_manage_permission=True)
        existing_code = next(iter(fx.repository.vouchers.values())).code
        result = await fx.service.import_vouchers(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
            codes=[existing_code, "FRESH-CODE"],
        )
        assert len(result.imported) == 1
        assert result.imported[0].code == "FRESH-CODE"
        assert any(code == existing_code for code, _ in result.rejected)

    async def test_import_into_revoked_batch_raises(self) -> None:
        fx = make_service()
        batch = await _create_batch(fx, quantity=0, has_manage_permission=True)
        await fx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=fx.organization.id,
        )
        with pytest.raises(VoucherBatchNotActiveError):
            await fx.service.import_vouchers(
                batch_id=batch.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=fx.organization.id,
                codes=["SHOULD-FAIL"],
            )


# ============================================================================
# Rate limiting
# ============================================================================


class TestRateLimiting:
    async def test_exceeding_redemption_rate_limit_raises(self) -> None:
        fx = make_service(redemption_max_attempts_per_window=2)
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        for _ in range(2):
            await fx.service.validate_voucher(code=voucher.code, source="9.9.9.9")
        with pytest.raises(VoucherRedemptionRateLimitExceededError):
            await fx.service.validate_voucher(code=voucher.code, source="9.9.9.9")

    async def test_rate_limit_is_scoped_per_source(self) -> None:
        fx = make_service(redemption_max_attempts_per_window=1)
        await _create_batch(fx, quantity=1, has_manage_permission=True)
        voucher = next(iter(fx.repository.vouchers.values()))
        await fx.service.validate_voucher(code=voucher.code, source="1.1.1.1")
        # A different source is unaffected by the first one's limit.
        await fx.service.validate_voucher(code=voucher.code, source="2.2.2.2")

    async def test_rate_limiter_direct_raises_with_retry_after(self) -> None:
        redis = FakeRedis()
        await VoucherRedemptionRateLimiter.check_and_increment(
            redis, "1.2.3.4", max_attempts=1, window_minutes=1
        )
        with pytest.raises(VoucherRedemptionRateLimitExceededError) as exc_info:
            await VoucherRedemptionRateLimiter.check_and_increment(
                redis, "1.2.3.4", max_attempts=1, window_minutes=1
            )
        assert exc_info.value.retry_after_seconds == 60

"""Unit tests for the Demo Request domain: the new structured
lead-qualification fields (``property_type``/``location_count``/
``router_count``), the ``compute_lead_priority`` triage signal, and
create/list/get/update service behavior.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_channel_partner.py``'s own module docstring);
``asyncio_mode = "auto"`` runs async tests directly.
``DemoRequestService`` is exercised against a small, hand-rolled in-memory
fake repository (mirroring ``test_channel_partner.py``'s own
``FakeChannelPartnerRepository`` shape) -- there is no live Postgres
connection in this environment. This domain previously had zero unit
tests -- a pre-existing gap, closed here alongside the new fields since
this module is already being touched.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.demo_request.constants import (
    DemoRequestLeadPriority,
    DemoRequestPropertyType,
    DemoRequestStatus,
)
from app.domains.demo_request.exceptions import DemoRequestNotFoundError
from app.domains.demo_request.models import DemoRequest
from app.domains.demo_request.schemas import (
    DemoRequestCreateRequest,
    DemoRequestUpdateRequest,
    compute_lead_priority,
)
from app.domains.demo_request.service import DemoRequestService

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
class FakeDemoRequestRepository:
    requests: dict[uuid.UUID, DemoRequest] = field(default_factory=dict)

    async def create(self, **fields: object) -> DemoRequest:
        demo_request = DemoRequest(**_base_fields(**fields))
        self.requests[demo_request.id] = demo_request
        return demo_request

    async def get_by_id(self, demo_request_id: uuid.UUID) -> DemoRequest | None:
        return self.requests.get(demo_request_id)

    async def update(
        self, demo_request: DemoRequest, data: dict[str, object]
    ) -> DemoRequest:
        for key, value in data.items():
            setattr(demo_request, key, value)
        demo_request.version += 1
        return demo_request

    async def list_records(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
        property_type: str | None = None,
    ) -> tuple[list[DemoRequest], PaginationMeta]:
        items = [r for r in self.requests.values() if not r.is_deleted]
        if status is not None:
            items = [r for r in items if r.status == status]
        if property_type is not None:
            items = [r for r in items if r.property_type == property_type]
        if search is not None:
            needle = search.lower()
            items = [
                r
                for r in items
                if needle in r.full_name.lower()
                or needle in r.email.lower()
                or needle in r.company_name.lower()
            ]
        items.sort(key=lambda r: r.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))


def _make_service() -> tuple[DemoRequestService, FakeDemoRequestRepository]:
    repository = FakeDemoRequestRepository()
    service = DemoRequestService(repository)
    return service, repository


def _make_request(**overrides: object) -> DemoRequestCreateRequest:
    fields: dict[str, object] = {
        "full_name": "Alice Anderson",
        "email": "alice@example.com",
        "company_name": "Lakeside Hotel",
    }
    fields.update(overrides)
    return DemoRequestCreateRequest(**fields)


# ============================================================================
# Schema validation: property_type / location_count / router_count
# ============================================================================


class TestDemoRequestCreateRequestValidation:
    def test_minimal_request_omits_all_new_fields(self) -> None:
        request = _make_request()
        assert request.property_type is None
        assert request.location_count is None
        assert request.router_count is None

    def test_valid_property_type_accepted(self) -> None:
        request = _make_request(property_type=DemoRequestPropertyType.HOTEL.value)
        assert request.property_type == "hotel"

    def test_every_enum_member_is_accepted(self) -> None:
        for member in DemoRequestPropertyType:
            request = _make_request(property_type=member.value)
            assert request.property_type == member.value

    def test_unknown_property_type_rejected(self) -> None:
        with pytest.raises(ValidationError, match="property_type must be one of"):
            _make_request(property_type="spaceship")

    def test_negative_location_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_request(location_count=-1)

    def test_negative_router_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_request(router_count=-1)

    def test_absurdly_large_location_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_request(location_count=100_000_001)

    def test_zero_location_count_is_valid(self) -> None:
        # 0 is a legitimate (if unusual) self-report -- only negative
        # values are nonsensical.
        request = _make_request(location_count=0)
        assert request.location_count == 0

    def test_valid_counts_accepted(self) -> None:
        request = _make_request(location_count=20, router_count=45)
        assert request.location_count == 20
        assert request.router_count == 45


class TestDemoRequestUpdateRequestValidation:
    def test_valid_status_accepted(self) -> None:
        update = DemoRequestUpdateRequest(status=DemoRequestStatus.CONTACTED.value)
        assert update.status == "contacted"

    def test_unknown_status_rejected(self) -> None:
        with pytest.raises(ValidationError, match="status must be one of"):
            DemoRequestUpdateRequest(status="won")


# ============================================================================
# compute_lead_priority
# ============================================================================


class TestComputeLeadPriority:
    def test_both_fields_none_is_unknown(self) -> None:
        assert (
            compute_lead_priority(None, None) == DemoRequestLeadPriority.UNKNOWN
        )

    def test_single_location_no_router_info_is_single_site(self) -> None:
        assert (
            compute_lead_priority(1, None) == DemoRequestLeadPriority.SINGLE_SITE
        )

    def test_zero_locations_treated_as_single_site(self) -> None:
        assert (
            compute_lead_priority(0, None) == DemoRequestLeadPriority.SINGLE_SITE
        )

    def test_single_location_many_routers_is_multi_router_single_site(self) -> None:
        assert (
            compute_lead_priority(1, 6)
            == DemoRequestLeadPriority.MULTI_ROUTER_SINGLE_SITE
        )

    def test_location_unknown_but_multiple_routers_is_multi_router_single_site(
        self,
    ) -> None:
        assert (
            compute_lead_priority(None, 3)
            == DemoRequestLeadPriority.MULTI_ROUTER_SINGLE_SITE
        )

    def test_location_unknown_single_router_is_single_site(self) -> None:
        assert (
            compute_lead_priority(None, 1) == DemoRequestLeadPriority.SINGLE_SITE
        )

    def test_two_locations_is_multi_location(self) -> None:
        assert (
            compute_lead_priority(2, None) == DemoRequestLeadPriority.MULTI_LOCATION
        )

    def test_ten_locations_is_still_multi_location(self) -> None:
        assert (
            compute_lead_priority(10, None)
            == DemoRequestLeadPriority.MULTI_LOCATION
        )

    def test_eleven_locations_is_enterprise(self) -> None:
        assert (
            compute_lead_priority(11, None) == DemoRequestLeadPriority.ENTERPRISE
        )

    def test_large_location_count_is_enterprise_regardless_of_routers(self) -> None:
        assert (
            compute_lead_priority(50, 2) == DemoRequestLeadPriority.ENTERPRISE
        )

    def test_multi_location_takes_priority_over_router_count(self) -> None:
        # location_count alone decides MULTI_LOCATION/ENTERPRISE -- router
        # count is only consulted in the single-site branch.
        assert (
            compute_lead_priority(3, 1) == DemoRequestLeadPriority.MULTI_LOCATION
        )


# ============================================================================
# Service: create (public submission)
# ============================================================================


class TestSubmitDemoRequest:
    async def test_submit_without_new_fields_still_works(self) -> None:
        service, _repository = _make_service()

        demo_request = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="ALICE@Example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
        )

        assert demo_request.property_type is None
        assert demo_request.location_count is None
        assert demo_request.router_count is None
        assert demo_request.email == "alice@example.com"

    async def test_submit_persists_lead_qualification_fields(self) -> None:
        service, repository = _make_service()

        demo_request = await service.submit_demo_request(
            full_name="Bob Brown",
            email="bob@example.com",
            phone="9876543210",
            company_name="Bob's Cafe Chain",
            message="20 locations, need it live by next quarter",
            property_type=DemoRequestPropertyType.CAFE_RESTAURANT.value,
            location_count=20,
            router_count=25,
        )

        assert demo_request.property_type == "cafe_restaurant"
        assert demo_request.location_count == 20
        assert demo_request.router_count == 25
        stored = repository.requests[demo_request.id]
        assert stored.location_count == 20

    async def test_submit_never_passes_status_explicitly(self) -> None:
        # The public submission path has no notion of status at all --
        # only Master-console updates ever set it (see
        # DemoRequestUpdateRequest's own docstring). Confirms
        # submit_demo_request's repository.create(**fields) call carries no
        # "status" key, leaving the column's own DB-side default
        # (DemoRequestStatus.NEW) to apply exactly once, at INSERT time.
        captured: dict[str, object] = {}

        @dataclass
        class _CapturingRepository(FakeDemoRequestRepository):
            async def create(self, **fields: object) -> DemoRequest:  # type: ignore[override]
                captured.update(fields)
                return await super().create(**fields)

        service = DemoRequestService(_CapturingRepository())
        await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
        )

        assert "status" not in captured


# ============================================================================
# Service: read (get/list) including the new property_type filter
# ============================================================================


class TestGetAndListDemoRequests:
    async def test_get_not_found_raises(self) -> None:
        service, _repository = _make_service()
        with pytest.raises(DemoRequestNotFoundError):
            await service.get_demo_request(uuid.uuid4())

    async def test_get_returns_submitted_request(self) -> None:
        service, _repository = _make_service()
        created = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
        )

        fetched = await service.get_demo_request(created.id)

        assert fetched.id == created.id

    async def test_list_filters_by_property_type(self) -> None:
        service, _repository = _make_service()
        hotel = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
            property_type=DemoRequestPropertyType.HOTEL.value,
        )
        await service.submit_demo_request(
            full_name="Bob Brown",
            email="bob@example.com",
            phone=None,
            company_name="Bob's Gym",
            message=None,
            property_type=DemoRequestPropertyType.GYM_FITNESS.value,
        )

        result = await service.list_demo_requests(
            property_type=DemoRequestPropertyType.HOTEL.value
        )

        assert len(result.items) == 1
        assert result.items[0].id == hotel.id

    async def test_list_without_property_type_returns_everything(self) -> None:
        service, _repository = _make_service()
        await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
            property_type=DemoRequestPropertyType.HOTEL.value,
        )
        await service.submit_demo_request(
            full_name="Bob Brown",
            email="bob@example.com",
            phone=None,
            company_name="Bob's Gym",
            message=None,
            property_type=DemoRequestPropertyType.GYM_FITNESS.value,
        )

        result = await service.list_demo_requests()

        assert len(result.items) == 2

    async def test_list_combines_status_and_property_type_filters(self) -> None:
        service, repository = _make_service()
        matching = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
            property_type=DemoRequestPropertyType.HOTEL.value,
        )
        other_status = await service.submit_demo_request(
            full_name="Carol Chen",
            email="carol@example.com",
            phone=None,
            company_name="Seaside Hotel",
            message=None,
            property_type=DemoRequestPropertyType.HOTEL.value,
        )
        # submit_demo_request never sets status explicitly (see
        # TestSubmitDemoRequest.test_submit_never_passes_status_explicitly)
        # -- the fake repository, unlike a real flush, never applies the
        # column's DB-side default, so both rows are set explicitly here
        # to exercise the filter combination realistically.
        await repository.update(matching, {"status": DemoRequestStatus.NEW.value})
        await repository.update(
            other_status, {"status": DemoRequestStatus.CLOSED.value}
        )

        result = await service.list_demo_requests(
            status=DemoRequestStatus.NEW.value,
            property_type=DemoRequestPropertyType.HOTEL.value,
        )

        assert len(result.items) == 1
        assert result.items[0].id == matching.id


# ============================================================================
# Service: update (Master console)
# ============================================================================


class TestUpdateDemoRequest:
    async def test_update_not_found_raises(self) -> None:
        service, _repository = _make_service()
        with pytest.raises(DemoRequestNotFoundError):
            await service.update_demo_request(
                demo_request_id=uuid.uuid4(),
                data={"status": DemoRequestStatus.CONTACTED.value},
                actor_user_id=uuid.uuid4(),
            )

    async def test_update_status_persists_and_sets_updated_by(self) -> None:
        service, _repository = _make_service()
        created = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
        )
        actor_id = uuid.uuid4()

        updated = await service.update_demo_request(
            demo_request_id=created.id,
            data={"status": DemoRequestStatus.CONTACTED.value},
            actor_user_id=actor_id,
        )

        assert updated.status == DemoRequestStatus.CONTACTED.value
        assert updated.updated_by == actor_id

    async def test_update_leaves_lead_qualification_fields_untouched(self) -> None:
        service, _repository = _make_service()
        created = await service.submit_demo_request(
            full_name="Alice Anderson",
            email="alice@example.com",
            phone=None,
            company_name="Lakeside Hotel",
            message=None,
            property_type=DemoRequestPropertyType.HOTEL.value,
            location_count=5,
        )

        updated = await service.update_demo_request(
            demo_request_id=created.id,
            data={"internal_notes": "followed up, no answer"},
            actor_user_id=uuid.uuid4(),
        )

        assert updated.property_type == "hotel"
        assert updated.location_count == 5


# ============================================================================
# Model
# ============================================================================


class TestDemoRequestModel:
    def test_repr_does_not_error_and_includes_email(self) -> None:
        demo_request = DemoRequest(
            **_base_fields(
                full_name="Alice Anderson",
                email="alice@example.com",
                company_name="Lakeside Hotel",
                status=DemoRequestStatus.NEW.value,
            )
        )
        assert "alice@example.com" in repr(demo_request)

    def test_new_fields_default_to_none_when_unset(self) -> None:
        demo_request = DemoRequest(
            **_base_fields(
                full_name="Alice Anderson",
                email="alice@example.com",
                company_name="Lakeside Hotel",
                status=DemoRequestStatus.NEW.value,
            )
        )
        assert demo_request.property_type is None
        assert demo_request.location_count is None
        assert demo_request.router_count is None

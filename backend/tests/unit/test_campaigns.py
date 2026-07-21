"""Unit tests for the Campaigns domain: pure validators (status
transitions, the runtime ``compute_effective_status`` re-derivation,
question/asset/display-rule validation), service-layer CRUD + tenant
isolation, lifecycle transitions, cloning (deep-copies questions/assets,
never responses/impressions), the guest-facing serving/respond/
impression flow (``EVERY_LOGIN``/``FIRST_LOGIN_ONLY``/
``ONCE_PER_N_DAYS`` eligibility, ``target_networks`` filtering), results
aggregation per ``AnswerType``, CSV export masking (flag on/off), and a
structural RBAC check mirroring ``tests/unit/test_qos.py``'s own
precedent -- adapted here to also assert the guest-facing router carries
*no* permission dependency at all, by design.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly. ``CampaignsService``
is exercised against small, hand-rolled in-memory fakes for its own
repository and every composed narrow Protocol -- mirrors
``test_qos.py``'s/``test_hotspot.py``'s identical "fake the narrow
Protocol boundary" precedent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.campaigns.constants import (
    CampaignStatus,
    CampaignType,
    DisplayRule,
)
from app.domains.campaigns.exceptions import (
    CampaignNotActiveError,
    CampaignNotFoundError,
    CampaignNotSchedulableError,
    CrossOrganizationCampaignAccessError,
    DuplicateFirstLoginResponseError,
    GuestSessionNotActiveError,
    GuestSessionNotFoundError,
    InvalidAssetUrlsError,
    InvalidCampaignStatusTransitionError,
    InvalidDisplayIntervalError,
    InvalidQuestionOptionsError,
    OrganizationRequiredError,
    WrongCampaignTypeError,
)
from app.domains.campaigns.models import (
    Campaign,
    CampaignAsset,
    CampaignImpression,
    CampaignQuestion,
    CampaignResponse,
)
from app.domains.campaigns.router import guest_router as campaigns_guest_router
from app.domains.campaigns.router import router as campaigns_router
from app.domains.campaigns.service import CampaignsService
from app.domains.campaigns.validators import (
    compute_effective_status,
    validate_asset_urls,
    validate_display_rule_fields,
    validate_question_options,
    validate_status_transition,
)
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.models import Guest, GuestSession
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.location.models import Location
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router
from app.middleware.request_context import MaskingContext, masking_context

# ============================================================================
# Shared helpers
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


def _make_organization(**overrides: object) -> Organization:
    base: dict[str, object] = {
        "name": "Test Org",
        "slug": f"org-{uuid.uuid4()}",
        "legal_name": None,
        "org_type": "standard",
        "status": "active",
        "parent_organization_id": None,
        "contact_email": "admin@example.com",
        "contact_phone": None,
        "timezone": "UTC",
        "default_locale": "en",
        "settings": {},
        "subscription_tier": None,
    }
    base.update(overrides)
    return Organization(**_base_fields(**base))


def _make_location(*, organization_id: uuid.UUID, **overrides: object) -> Location:
    base: dict[str, object] = {
        "organization_id": organization_id,
        "name": "Test Location",
        "slug": f"loc-{uuid.uuid4()}",
        "status": "active",
        "address_line1": "1 Main St",
        "address_line2": None,
        "city": "Austin",
        "state_province": "TX",
        "postal_code": "78701",
        "country": "US",
        "timezone": "UTC",
        "latitude": None,
        "longitude": None,
        "contact_name": None,
        "contact_phone": None,
        "contact_email": None,
        "settings": {},
    }
    base.update(overrides)
    return Location(**_base_fields(**base))


def _make_router(
    *, organization_id: uuid.UUID, location_id: uuid.UUID, **overrides: object
) -> Router:
    base: dict[str, object] = {
        "organization_id": organization_id,
        "location_id": location_id,
        "name": "Test Router",
        "serial_number": f"SN-{uuid.uuid4().hex[:8]}",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "model": "RB4011",
        "vendor": "mikrotik",
        "routeros_version": None,
        "management_ip_address": "10.0.0.1",
        "public_ip_address": None,
        "status": "online",
        "last_seen_at": None,
        "last_health_check_at": None,
        "health_status": None,
        "api_username": "admin",
        "api_credentials_encrypted": "encrypted-placeholder",
        "settings": {},
    }
    base.update(overrides)
    return Router(**_base_fields(**base))


def _make_guest(
    *, organization_id: uuid.UUID, location_id: uuid.UUID | None, **overrides: object
) -> Guest:
    base: dict[str, object] = {
        "organization_id": organization_id,
        "location_id": location_id,
        "identifier": "9999999999",
        "display_name": "Test Guest",
        "first_seen_at": _now(),
        "last_seen_at": _now(),
    }
    base.update(overrides)
    return Guest(**_base_fields(**base))


def _make_guest_session(
    *,
    guest_id: uuid.UUID,
    router_id: uuid.UUID,
    location_id: uuid.UUID,
    organization_id: uuid.UUID,
    status: str = GuestSessionStatus.ACTIVE.value,
    **overrides: object,
) -> GuestSession:
    base: dict[str, object] = {
        "guest_id": guest_id,
        "device_id": None,
        "router_id": router_id,
        "location_id": location_id,
        "organization_id": organization_id,
        "auth_method": "otp",
        "voucher_id": None,
        "status": status,
        "started_at": _now(),
        "ended_at": None,
        "last_activity_at": _now(),
        "ip_address": None,
    }
    base.update(overrides)
    return GuestSession(**_base_fields(**base))


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeCampaignsRepository:
    campaigns: dict[uuid.UUID, Campaign] = field(default_factory=dict)
    questions: dict[uuid.UUID, CampaignQuestion] = field(default_factory=dict)
    responses: dict[uuid.UUID, CampaignResponse] = field(default_factory=dict)
    assets: dict[uuid.UUID, CampaignAsset] = field(default_factory=dict)
    impressions: dict[uuid.UUID, CampaignImpression] = field(default_factory=dict)
    # test-only lookup: guest_session_id -> guest_id, so has_guest_been_shown/
    # get_last_shown_at can join the way the real join-based repository does.
    session_guest_map: dict[uuid.UUID, uuid.UUID] = field(default_factory=dict)

    # -- Campaign ----------------------------------------------------------

    async def create_campaign(self, **fields: object) -> Campaign:
        campaign = Campaign(**_base_fields(**fields))
        self.campaigns[campaign.id] = campaign
        return campaign

    async def get_campaign_by_id(
        self, campaign_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Campaign | None:
        campaign = self.campaigns.get(campaign_id)
        if campaign is None or (campaign.is_deleted and not include_deleted):
            return None
        return campaign

    async def update_campaign(
        self, campaign: Campaign, data: dict[str, object]
    ) -> Campaign:
        for key, value in data.items():
            setattr(campaign, key, value)
        campaign.version += 1
        return campaign

    async def soft_delete_campaign(self, campaign: Campaign) -> Campaign:
        campaign.is_deleted = True
        campaign.deleted_at = _now()
        return campaign

    async def list_campaigns(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ):
        values = [c for c in self.campaigns.values() if not c.is_deleted]
        if requesting_organization_id is not None:
            values = [
                c for c in values if c.organization_id == requesting_organization_id
            ]
        if location_id is not None:
            values = [c for c in values if c.location_id == location_id]
        return values, None

    async def list_non_terminal_campaigns(self) -> list[Campaign]:
        return [
            c
            for c in self.campaigns.values()
            if not c.is_deleted
            and c.status
            in (CampaignStatus.SCHEDULED.value, CampaignStatus.ACTIVE.value)
        ]

    async def list_candidate_campaigns(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> list[Campaign]:
        result = []
        for c in self.campaigns.values():
            if c.is_deleted or c.organization_id != organization_id:
                continue
            if c.status not in (
                CampaignStatus.SCHEDULED.value,
                CampaignStatus.ACTIVE.value,
            ):
                continue
            if c.location_id is not None and c.location_id != location_id:
                continue
            result.append(c)
        return result

    # -- CampaignQuestion ----------------------------------------------------

    async def create_question(self, **fields: object) -> CampaignQuestion:
        question = CampaignQuestion(**_base_fields(**fields))
        self.questions[question.id] = question
        return question

    async def get_question_by_id(
        self, question_id: uuid.UUID
    ) -> CampaignQuestion | None:
        question = self.questions.get(question_id)
        if question is None or question.is_deleted:
            return None
        return question

    async def update_question(
        self, question: CampaignQuestion, data: dict[str, object]
    ) -> CampaignQuestion:
        for key, value in data.items():
            setattr(question, key, value)
        question.version += 1
        return question

    async def soft_delete_question(
        self, question: CampaignQuestion
    ) -> CampaignQuestion:
        question.is_deleted = True
        question.deleted_at = _now()
        return question

    async def list_questions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignQuestion]:
        values = [
            q
            for q in self.questions.values()
            if q.campaign_id == campaign_id and not q.is_deleted
        ]
        values.sort(key=lambda q: q.order_index)
        return values

    # -- CampaignResponse ----------------------------------------------------

    async def create_response(self, **fields: object) -> CampaignResponse:
        response = CampaignResponse(**_base_fields(**fields))
        self.responses[response.id] = response
        return response

    async def get_response_for_campaign_and_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> CampaignResponse | None:
        for response in self.responses.values():
            if response.campaign_id == campaign_id and response.guest_id == guest_id:
                return response
        return None

    async def list_responses_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignResponse]:
        return [r for r in self.responses.values() if r.campaign_id == campaign_id]

    async def count_responses_for_campaign(self, campaign_id: uuid.UUID) -> int:
        return len(await self.list_responses_for_campaign(campaign_id))

    # -- CampaignAsset -------------------------------------------------------

    async def create_asset(self, **fields: object) -> CampaignAsset:
        asset = CampaignAsset(**_base_fields(**fields))
        self.assets[asset.id] = asset
        return asset

    async def get_asset_by_id(self, asset_id: uuid.UUID) -> CampaignAsset | None:
        asset = self.assets.get(asset_id)
        if asset is None or asset.is_deleted:
            return None
        return asset

    async def update_asset(
        self, asset: CampaignAsset, data: dict[str, object]
    ) -> CampaignAsset:
        for key, value in data.items():
            setattr(asset, key, value)
        asset.version += 1
        return asset

    async def soft_delete_asset(self, asset: CampaignAsset) -> CampaignAsset:
        asset.is_deleted = True
        asset.deleted_at = _now()
        return asset

    async def list_assets_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignAsset]:
        return [a for a in self.assets.values() if a.campaign_id == campaign_id]

    # -- CampaignImpression --------------------------------------------------

    async def create_impression(self, **fields: object) -> CampaignImpression:
        impression = CampaignImpression(**_base_fields(**fields))
        self.impressions[impression.id] = impression
        self.session_guest_map.setdefault(impression.guest_session_id, None)
        return impression

    async def has_guest_been_shown_campaign(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> bool:
        for impression in self.impressions.values():
            if impression.campaign_id != campaign_id:
                continue
            if self.session_guest_map.get(impression.guest_session_id) == guest_id:
                return True
        return False

    async def get_last_shown_at_for_guest(
        self, campaign_id: uuid.UUID, guest_id: uuid.UUID
    ) -> datetime | None:
        latest: datetime | None = None
        for impression in self.impressions.values():
            if impression.campaign_id != campaign_id:
                continue
            if self.session_guest_map.get(impression.guest_session_id) != guest_id:
                continue
            if latest is None or impression.shown_at > latest:
                latest = impression.shown_at
        return latest

    async def list_impressions_for_campaign(
        self, campaign_id: uuid.UUID
    ) -> list[CampaignImpression]:
        return [i for i in self.impressions.values() if i.campaign_id == campaign_id]


@dataclass
class FakeOrganizationLookup:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    def add(self, organization: Organization) -> Organization:
        self.organizations[organization.id] = organization
        return organization

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None:
            raise OrganizationNotFoundError(organization_id)
        return organization


@dataclass
class FakeLocationLookup:
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    def add(self, location: Location) -> Location:
        self.locations[location.id] = location
        return location

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None:
            raise LocationNotFoundError(location_id)
        return location


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        return router


@dataclass
class FakeGuestSessionLookup:
    sessions: dict[uuid.UUID, GuestSession] = field(default_factory=dict)
    guests: dict[uuid.UUID, Guest] = field(default_factory=dict)

    def add_session(self, session: GuestSession) -> GuestSession:
        self.sessions[session.id] = session
        return session

    def add_guest(self, guest: Guest) -> Guest:
        self.guests[guest.id] = guest
        return guest

    async def get_session_by_id(self, session_id: uuid.UUID) -> GuestSession | None:
        return self.sessions.get(session_id)

    async def get_guest_by_id(self, guest_id: uuid.UUID) -> Guest | None:
        return self.guests.get(guest_id)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: CampaignsService
    repository: FakeCampaignsRepository
    organization_lookup: FakeOrganizationLookup
    location_lookup: FakeLocationLookup
    router_lookup: FakeRouterLookup
    guest_session_lookup: FakeGuestSessionLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeCampaignsRepository()
    organization_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    router_lookup = FakeRouterLookup()
    guest_session_lookup = FakeGuestSessionLookup()
    audit_writer = FakeAuditLogWriter()
    service = CampaignsService(
        repository,
        organization_lookup,
        location_lookup,
        router_lookup,
        guest_session_lookup,
        audit_writer=audit_writer,
    )
    return Harness(
        service=service,
        repository=repository,
        organization_lookup=organization_lookup,
        location_lookup=location_lookup,
        router_lookup=router_lookup,
        guest_session_lookup=guest_session_lookup,
        audit_writer=audit_writer,
    )


async def _create_campaign(
    h: Harness,
    organization: Organization,
    *,
    location_id: uuid.UUID | None = None,
    name: str = "Welcome Survey",
    campaign_type: CampaignType = CampaignType.SURVEY,
    starts_at: datetime | None = None,
    ends_at: datetime | None = None,
    display_rule: DisplayRule = DisplayRule.EVERY_LOGIN,
    display_interval_days: int | None = None,
    target_networks: list[str] | None = None,
    is_skippable: bool = True,
) -> Campaign:
    return await h.service.create_campaign(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=organization.id,
        location_id=location_id,
        name=name,
        campaign_type=campaign_type,
        starts_at=starts_at,
        ends_at=ends_at,
        display_rule=display_rule,
        display_interval_days=display_interval_days,
        target_networks=target_networks or [],
        is_skippable=is_skippable,
    )


# ============================================================================
# Validators: compute_effective_status
# ============================================================================


class TestComputeEffectiveStatus:
    def test_draft_is_stable(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.DRAFT, starts_at=None, ends_at=None, now=now
            )
            == CampaignStatus.DRAFT
        )

    def test_paused_is_stable(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.PAUSED, starts_at=None, ends_at=None, now=now
            )
            == CampaignStatus.PAUSED
        )

    def test_scheduled_before_start_stays_scheduled(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.SCHEDULED,
                starts_at=now + timedelta(hours=1),
                ends_at=None,
                now=now,
            )
            == CampaignStatus.SCHEDULED
        )

    def test_scheduled_after_start_becomes_active(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.SCHEDULED,
                starts_at=now - timedelta(hours=1),
                ends_at=None,
                now=now,
            )
            == CampaignStatus.ACTIVE
        )

    def test_active_after_end_becomes_ended(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.ACTIVE,
                starts_at=now - timedelta(days=1),
                ends_at=now - timedelta(hours=1),
                now=now,
            )
            == CampaignStatus.ENDED
        )

    def test_active_with_no_end_stays_active(self) -> None:
        now = _now()
        assert (
            compute_effective_status(
                CampaignStatus.ACTIVE, starts_at=None, ends_at=None, now=now
            )
            == CampaignStatus.ACTIVE
        )


class TestValidateStatusTransition:
    def test_draft_to_scheduled_is_legal(self) -> None:
        validate_status_transition(CampaignStatus.DRAFT, CampaignStatus.SCHEDULED)

    def test_draft_to_active_is_illegal(self) -> None:
        with pytest.raises(InvalidCampaignStatusTransitionError):
            validate_status_transition(CampaignStatus.DRAFT, CampaignStatus.ACTIVE)

    def test_ended_has_no_outgoing_transitions(self) -> None:
        for target in CampaignStatus:
            if target == CampaignStatus.ENDED:
                continue
            with pytest.raises(InvalidCampaignStatusTransitionError):
                validate_status_transition(CampaignStatus.ENDED, target)


class TestValidateQuestionOptions:
    def test_single_choice_requires_options(self) -> None:
        from app.domains.campaigns.constants import AnswerType

        with pytest.raises(InvalidQuestionOptionsError):
            validate_question_options(AnswerType.SINGLE_CHOICE, [])

    def test_free_text_forbids_options(self) -> None:
        from app.domains.campaigns.constants import AnswerType

        with pytest.raises(InvalidQuestionOptionsError):
            validate_question_options(AnswerType.FREE_TEXT, ["a"])

    def test_rating_5_accepts_no_options(self) -> None:
        from app.domains.campaigns.constants import AnswerType

        validate_question_options(AnswerType.RATING_5, [])


class TestValidateAssetUrls:
    def test_requires_at_least_one_url(self) -> None:
        with pytest.raises(InvalidAssetUrlsError):
            validate_asset_urls(None, None)

    def test_accepts_image_url_only(self) -> None:
        validate_asset_urls("https://example.com/a.png", None)


class TestValidateDisplayRuleFields:
    def test_once_per_n_days_requires_positive_interval(self) -> None:
        with pytest.raises(InvalidDisplayIntervalError):
            validate_display_rule_fields(DisplayRule.ONCE_PER_N_DAYS, None)
        with pytest.raises(InvalidDisplayIntervalError):
            validate_display_rule_fields(DisplayRule.ONCE_PER_N_DAYS, 0)

    def test_every_login_ignores_interval(self) -> None:
        validate_display_rule_fields(DisplayRule.EVERY_LOGIN, None)


# ============================================================================
# Service: Campaign CRUD + tenant isolation
# ============================================================================


class TestCampaignCrud:
    async def test_create_campaign_succeeds(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)

        campaign = await _create_campaign(h, org, name="Feedback")

        assert campaign.name == "Feedback"
        assert campaign.status == CampaignStatus.DRAFT.value
        assert campaign.organization_id == org.id

    async def test_create_without_organization_header_raises(self) -> None:
        h = make_harness()
        with pytest.raises(OrganizationRequiredError):
            await h.service.create_campaign(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=None,
                location_id=None,
                name="X",
                campaign_type=CampaignType.SURVEY,
                starts_at=None,
                ends_at=None,
                display_rule=DisplayRule.EVERY_LOGIN,
                display_interval_days=None,
                target_networks=[],
                is_skippable=True,
            )

    async def test_get_campaign_cross_organization_raises(self) -> None:
        h = make_harness()
        org = _make_organization()
        other_org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org)

        with pytest.raises(CrossOrganizationCampaignAccessError):
            await h.service.get_campaign(
                campaign.id, requesting_organization_id=other_org.id
            )

    async def test_get_campaign_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(CampaignNotFoundError):
            await h.service.get_campaign(uuid.uuid4())

    async def test_update_campaign_changes_fields(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org)

        updated = await h.service.update_campaign(
            campaign.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            name="Renamed",
        )
        assert updated.name == "Renamed"

    async def test_delete_campaign_soft_deletes(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org)

        deleted = await h.service.delete_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )
        assert deleted.is_deleted is True


# ============================================================================
# Service: lifecycle transitions
# ============================================================================


class TestLifecycleTransitions:
    async def test_schedule_requires_starts_at(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, starts_at=None)

        with pytest.raises(CampaignNotSchedulableError):
            await h.service.schedule_campaign(
                campaign.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=org.id,
            )

    async def test_schedule_pause_resume_end_flow(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, starts_at=_now() + timedelta(hours=1))

        scheduled = await h.service.schedule_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )
        assert scheduled.status == CampaignStatus.SCHEDULED.value

        active = await h.service.resume_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )
        assert active.status == CampaignStatus.ACTIVE.value

        paused = await h.service.pause_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )
        assert paused.status == CampaignStatus.PAUSED.value

        ended = await h.service.end_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )
        assert ended.status == CampaignStatus.ENDED.value

        with pytest.raises(InvalidCampaignStatusTransitionError):
            await h.service.resume_campaign(
                campaign.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=org.id,
            )

    async def test_sweep_status_transitions_moves_scheduled_to_active(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, starts_at=_now() - timedelta(hours=1))
        await h.service.schedule_campaign(
            campaign.id, actor_user_id=uuid.uuid4(), requesting_organization_id=org.id
        )

        transitioned = await h.service.sweep_status_transitions()

        assert transitioned == 1
        refreshed = await h.service.get_campaign(campaign.id)
        assert refreshed.status == CampaignStatus.ACTIVE.value


# ============================================================================
# Service: clone
# ============================================================================


class TestCloneCampaign:
    async def test_clone_deep_copies_questions_and_assets_not_responses(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        source = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)
        await h.service.add_question(
            source.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            order_index=0,
            question_text="How was it?",
            answer_type=__import__(
                "app.domains.campaigns.constants", fromlist=["AnswerType"]
            ).AnswerType.RATING_5,
            options=[],
            is_required=True,
        )

        clone = await h.service.clone_campaign(
            source.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            new_name="Welcome Survey (Copy)",
        )

        assert clone.id != source.id
        assert clone.name == "Welcome Survey (Copy)"
        assert clone.status == CampaignStatus.DRAFT.value
        clone_questions = await h.repository.list_questions_for_campaign(clone.id)
        assert len(clone_questions) == 1
        assert (
            clone_questions[0].id
            != (await h.repository.list_questions_for_campaign(source.id))[0].id
        )


# ============================================================================
# Service: guest-facing serving
# ============================================================================


class TestGetNextCampaignForSession:
    def _setup(self, h: Harness):
        org = _make_organization()
        location = _make_location(organization_id=org.id)
        router = _make_router(organization_id=org.id, location_id=location.id)
        h.organization_lookup.add(org)
        h.location_lookup.add(location)
        h.router_lookup.add(router)
        guest = _make_guest(organization_id=org.id, location_id=location.id)
        session = _make_guest_session(
            guest_id=guest.id,
            router_id=router.id,
            location_id=location.id,
            organization_id=org.id,
        )
        h.guest_session_lookup.add_guest(guest)
        h.guest_session_lookup.add_session(session)
        return org, location, router, guest, session

    async def test_returns_none_when_no_active_campaigns(self) -> None:
        h = make_harness()
        _, _, _, _, session = self._setup(h)
        result = await h.service.get_next_campaign_for_session(session.id)
        assert result is None

    async def test_returns_active_every_login_campaign(self) -> None:
        h = make_harness()
        org, _, _, _, session = self._setup(h)
        campaign = await _create_campaign(h, org, display_rule=DisplayRule.EVERY_LOGIN)
        campaign.status = CampaignStatus.ACTIVE.value

        result = await h.service.get_next_campaign_for_session(session.id)

        assert result is not None
        assert result.campaign.id == campaign.id

    async def test_target_networks_filters_out_other_routers(self) -> None:
        h = make_harness()
        org, location, _, _, session = self._setup(h)
        other_router = _make_router(organization_id=org.id, location_id=location.id)
        h.router_lookup.add(other_router)
        campaign = await _create_campaign(
            h,
            org,
            display_rule=DisplayRule.EVERY_LOGIN,
            target_networks=[str(other_router.id)],
        )
        campaign.status = CampaignStatus.ACTIVE.value

        result = await h.service.get_next_campaign_for_session(session.id)
        assert result is None

    async def test_first_login_only_excludes_guest_already_shown(self) -> None:
        h = make_harness()
        org, _, _, guest, session = self._setup(h)
        campaign = await _create_campaign(
            h, org, display_rule=DisplayRule.FIRST_LOGIN_ONLY
        )
        campaign.status = CampaignStatus.ACTIVE.value
        h.repository.session_guest_map[session.id] = guest.id
        await h.repository.create_impression(
            campaign_id=campaign.id,
            guest_session_id=session.id,
            shown_at=_now(),
            was_skipped=False,
            was_clicked=False,
        )

        result = await h.service.get_next_campaign_for_session(session.id)
        assert result is None

    async def test_once_per_n_days_excludes_recently_shown_guest(self) -> None:
        h = make_harness()
        org, _, _, guest, session = self._setup(h)
        campaign = await _create_campaign(
            h,
            org,
            display_rule=DisplayRule.ONCE_PER_N_DAYS,
            display_interval_days=7,
        )
        campaign.status = CampaignStatus.ACTIVE.value
        h.repository.session_guest_map[session.id] = guest.id
        await h.repository.create_impression(
            campaign_id=campaign.id,
            guest_session_id=session.id,
            shown_at=_now() - timedelta(days=1),
            was_skipped=False,
            was_clicked=False,
        )

        result = await h.service.get_next_campaign_for_session(session.id)
        assert result is None

    async def test_once_per_n_days_allows_after_interval_elapses(self) -> None:
        h = make_harness()
        org, _, _, guest, session = self._setup(h)
        campaign = await _create_campaign(
            h,
            org,
            display_rule=DisplayRule.ONCE_PER_N_DAYS,
            display_interval_days=7,
        )
        campaign.status = CampaignStatus.ACTIVE.value
        h.repository.session_guest_map[session.id] = guest.id
        await h.repository.create_impression(
            campaign_id=campaign.id,
            guest_session_id=session.id,
            shown_at=_now() - timedelta(days=10),
            was_skipped=False,
            was_clicked=False,
        )

        result = await h.service.get_next_campaign_for_session(session.id)
        assert result is not None
        assert result.campaign.id == campaign.id

    async def test_unknown_session_raises(self) -> None:
        h = make_harness()
        with pytest.raises(GuestSessionNotFoundError):
            await h.service.get_next_campaign_for_session(uuid.uuid4())

    async def test_inactive_session_raises(self) -> None:
        h = make_harness()
        org, location, router, guest, session = self._setup(h)
        session.status = GuestSessionStatus.EXPIRED.value

        with pytest.raises(GuestSessionNotActiveError):
            await h.service.get_next_campaign_for_session(session.id)


# ============================================================================
# Service: submit_response / record_impression
# ============================================================================


class TestSubmitResponse:
    def _setup(self, h: Harness):
        org = _make_organization()
        location = _make_location(organization_id=org.id)
        router = _make_router(organization_id=org.id, location_id=location.id)
        h.organization_lookup.add(org)
        h.location_lookup.add(location)
        h.router_lookup.add(router)
        guest = _make_guest(organization_id=org.id, location_id=location.id)
        session = _make_guest_session(
            guest_id=guest.id,
            router_id=router.id,
            location_id=location.id,
            organization_id=org.id,
        )
        h.guest_session_lookup.add_guest(guest)
        h.guest_session_lookup.add_session(session)
        h.repository.session_guest_map[session.id] = guest.id
        return org, guest, session

    async def test_submit_response_succeeds_for_active_survey(self) -> None:
        h = make_harness()
        org, guest, session = self._setup(h)
        campaign = await _create_campaign(
            h,
            org,
            campaign_type=CampaignType.SURVEY,
            display_rule=DisplayRule.EVERY_LOGIN,
        )
        campaign.status = CampaignStatus.ACTIVE.value

        response = await h.service.submit_response(
            campaign.id, guest_session_id=session.id, answers={"q1": "yes"}
        )
        assert response.guest_id == guest.id
        assert response.answers == {"q1": "yes"}

    async def test_submit_response_rejects_non_active_campaign(self) -> None:
        h = make_harness()
        org, guest, session = self._setup(h)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)

        with pytest.raises(CampaignNotActiveError):
            await h.service.submit_response(
                campaign.id, guest_session_id=session.id, answers={}
            )

    async def test_submit_response_rejects_non_survey_campaign(self) -> None:
        h = make_harness()
        org, guest, session = self._setup(h)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.BANNER)
        campaign.status = CampaignStatus.ACTIVE.value

        with pytest.raises(WrongCampaignTypeError):
            await h.service.submit_response(
                campaign.id, guest_session_id=session.id, answers={}
            )

    async def test_first_login_only_rejects_duplicate_response(self) -> None:
        h = make_harness()
        org, guest, session = self._setup(h)
        campaign = await _create_campaign(
            h,
            org,
            campaign_type=CampaignType.SURVEY,
            display_rule=DisplayRule.FIRST_LOGIN_ONLY,
        )
        campaign.status = CampaignStatus.ACTIVE.value
        await h.service.submit_response(
            campaign.id, guest_session_id=session.id, answers={"q1": "a"}
        )

        with pytest.raises(DuplicateFirstLoginResponseError):
            await h.service.submit_response(
                campaign.id, guest_session_id=session.id, answers={"q1": "b"}
            )

    async def test_record_impression_creates_row(self) -> None:
        h = make_harness()
        org, guest, session = self._setup(h)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.BANNER)

        impression = await h.service.record_impression(
            campaign.id, guest_session_id=session.id, was_skipped=True
        )
        assert impression.was_skipped is True
        assert impression.campaign_id == campaign.id


# ============================================================================
# Service: results aggregation
# ============================================================================


class TestResultsAggregation:
    async def test_aggregates_single_choice_and_rating_breakdowns(self) -> None:
        from app.domains.campaigns.constants import AnswerType

        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)
        q1 = await h.service.add_question(
            campaign.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            order_index=0,
            question_text="Pick one",
            answer_type=AnswerType.SINGLE_CHOICE,
            options=["yes", "no"],
            is_required=True,
        )
        q2 = await h.service.add_question(
            campaign.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            order_index=1,
            question_text="Rate us",
            answer_type=AnswerType.RATING_5,
            options=[],
            is_required=True,
        )
        await h.repository.create_response(
            campaign_id=campaign.id,
            guest_id=uuid.uuid4(),
            guest_session_id=uuid.uuid4(),
            submitted_at=_now(),
            answers={str(q1.id): "yes", str(q2.id): 5},
        )
        await h.repository.create_response(
            campaign_id=campaign.id,
            guest_id=uuid.uuid4(),
            guest_session_id=uuid.uuid4(),
            submitted_at=_now(),
            answers={str(q1.id): "no", str(q2.id): 3},
        )

        results = await h.service.get_results(
            campaign.id, requesting_organization_id=org.id
        )

        assert results.total_responses == 2
        by_id = {b.question_id: b for b in results.question_breakdowns}
        assert by_id[q1.id].option_counts == {"yes": 1, "no": 1}
        assert by_id[q2.id].average_rating == 4.0
        assert by_id[q2.id].rating_distribution == {5: 1, 3: 1}


# ============================================================================
# Service: CSV export masking
# ============================================================================


class TestExportResultsCsv:
    async def test_export_masks_guest_identity_when_masking_enabled(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)
        guest = _make_guest(
            organization_id=org.id, location_id=None, identifier="9876543210"
        )
        h.guest_session_lookup.add_guest(guest)
        await h.repository.create_response(
            campaign_id=campaign.id,
            guest_id=guest.id,
            guest_session_id=uuid.uuid4(),
            submitted_at=_now(),
            answers={},
        )

        token = masking_context.set(MaskingContext(masking_enabled=True))
        try:
            csv_text = await h.service.export_results_csv(
                campaign.id, requesting_organization_id=org.id
            )
        finally:
            masking_context.reset(token)

        assert "9876543210" not in csv_text
        assert "X" in csv_text

    async def test_export_shows_raw_guest_identity_when_masking_disabled(self) -> None:
        h = make_harness()
        org = _make_organization()
        h.organization_lookup.add(org)
        campaign = await _create_campaign(h, org, campaign_type=CampaignType.SURVEY)
        guest = _make_guest(
            organization_id=org.id, location_id=None, identifier="9876543210"
        )
        h.guest_session_lookup.add_guest(guest)
        await h.repository.create_response(
            campaign_id=campaign.id,
            guest_id=guest.id,
            guest_session_id=uuid.uuid4(),
            submitted_at=_now(),
            answers={},
        )

        token = masking_context.set(MaskingContext(masking_enabled=False))
        try:
            csv_text = await h.service.export_results_csv(
                campaign.id, requesting_organization_id=org.id
            )
        finally:
            masking_context.reset(token)

        assert "9876543210" in csv_text


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestRoutePermissionStructure:
    def test_every_admin_campaigns_route_has_a_permission_dependency(self) -> None:
        assert len(campaigns_router.routes) > 0
        for route in campaigns_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"

    def test_every_guest_facing_campaigns_route_has_no_permission_dependency(
        self,
    ) -> None:
        assert len(campaigns_guest_router.routes) == 3
        for route in campaigns_guest_router.routes:
            assert route.dependencies == [], (
                f"{route.path} ({route.methods}) unexpectedly carries a "
                "permission dependency -- guest-facing endpoints must stay "
                "zero-auth, see router.py's own module docstring"
            )

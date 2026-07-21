"""Business logic for the Campaigns domain -- CRUD, lifecycle transitions,
cloning, guest-facing serving/response/impression recording, and results
aggregation/export.

Never resolves an organization/location/router/guest session itself --
``OrganizationLookupProtocol``/``LocationLookupProtocol``/
``RouterLookupProtocol``/``GuestSessionLookupProtocol`` are the same
narrow, duck-typed Protocol composition-over-duplication pattern every
other domain's service uses (see ``app.domains.qos.service``'s own
identical shape).
"""

from __future__ import annotations

import csv
import io
import logging
import uuid
from collections import Counter
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import BaseModel as PydanticModel

from app.common.masking import MaskedIdentifier, MaskedName
from app.database.utils.pagination import PaginationMeta
from app.domains.guest.constants import GuestSessionStatus
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEFAULT_DISPLAY_INTERVAL_DAYS,
    AnswerType,
    CampaignStatus,
    CampaignType,
    DisplayRule,
)
from .events import (
    CampaignCreated,
    CampaignDeleted,
    CampaignImpressionRecorded,
    CampaignResponseSubmitted,
    CampaignStatusChanged,
    CampaignUpdated,
)
from .exceptions import (
    CampaignAssetNotFoundError,
    CampaignNotActiveError,
    CampaignNotFoundError,
    CampaignNotSchedulableError,
    CampaignQuestionNotFoundError,
    CrossOrganizationCampaignAccessError,
    DuplicateFirstLoginResponseError,
    GuestSessionNotActiveError,
    GuestSessionNotFoundError,
    OrganizationRequiredError,
    WrongCampaignTypeError,
)
from .models import (
    Campaign,
    CampaignAsset,
    CampaignImpression,
    CampaignQuestion,
    CampaignResponse,
)
from .repository import CampaignsRepositoryProtocol
from .validators import (
    compute_effective_status,
    validate_asset_urls,
    validate_display_rule_fields,
    validate_question_options,
    validate_status_transition,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OrganizationLookupProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class GuestSessionLookupProtocol(Protocol):
    """The subset of ``app.domains.guest.repository.GuestRepositoryProtocol``
    this module needs to resolve a guest session/guest identity for the
    guest-facing endpoints -- reused directly, never reimplemented."""

    async def get_session_by_id(self, session_id: uuid.UUID) -> object | None: ...

    async def get_guest_by_id(self, guest_id: uuid.UUID) -> object | None: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class NextCampaignResult:
    """The full servable content for one campaign, resolved for one guest
    session -- ``questions`` populated only for ``SURVEY``, ``asset`` only
    for ``BANNER``/``REDIRECT`` (see ``CampaignType``'s own docstring)."""

    campaign: Campaign
    questions: list[CampaignQuestion]
    asset: CampaignAsset | None


@dataclass(frozen=True, slots=True)
class QuestionResultBreakdown:
    """Per-question aggregation of every ``CampaignResponse.answers``
    submitted for a ``SURVEY`` campaign. Exactly one of
    ``option_counts``/``rating_distribution``/``free_text_answers`` is
    populated, keyed by ``answer_type`` -- the other two stay ``None``."""

    question_id: uuid.UUID
    question_text: str
    answer_type: str
    total_answers: int
    option_counts: dict[str, int] | None
    average_rating: float | None
    rating_distribution: dict[int, int] | None
    free_text_answers: list[str] | None


@dataclass(frozen=True, slots=True)
class CampaignResults:
    campaign_id: uuid.UUID
    total_responses: int
    total_impressions: int
    total_skipped: int
    total_clicked: int
    question_breakdowns: list[QuestionResultBreakdown]


class _ResultsExportRow(PydanticModel):
    """Internal-only helper reused purely to run a CSV export row through
    the exact same ``Masked*``/``PlainSerializer`` mechanism (context
    check + audit-bypass recording) every JSON response already uses --
    a hand-rolled "check the masking flag, call mask_identifier()" in
    this module would duplicate, and could silently drift from, that
    logic. Never returned from an endpoint; not part of the public API
    surface."""

    guest_identifier: MaskedIdentifier
    guest_name: MaskedName


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclass_fields(event)
    }


class CampaignsService:
    """Business logic for post-login guest campaigns. See
    ``app.domains.campaigns``'s own module docstring for the
    friction-avoidance/runtime-status design write-up this class
    implements."""

    def __init__(
        self,
        repository: CampaignsRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        router_lookup: RouterLookupProtocol,
        guest_session_lookup: GuestSessionLookupProtocol,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.router_lookup = router_lookup
        self.guest_session_lookup = guest_session_lookup
        self.audit_writer = audit_writer

    # ========================================================================
    # Campaign CRUD
    # ========================================================================

    async def create_campaign(
        self,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        name: str,
        campaign_type: CampaignType,
        starts_at: datetime | None,
        ends_at: datetime | None,
        display_rule: DisplayRule,
        display_interval_days: int | None,
        target_networks: list[str],
        is_skippable: bool,
    ) -> Campaign:
        if requesting_organization_id is None:
            raise OrganizationRequiredError()
        organization_id = requesting_organization_id
        await self.organization_lookup.get_organization(organization_id)
        if location_id is not None:
            await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization_id
            )
        for router_id in target_networks:
            await self.router_lookup.get_router(
                uuid.UUID(router_id), requesting_organization_id=organization_id
            )
        validate_display_rule_fields(display_rule, display_interval_days)

        campaign = await self.repository.create_campaign(
            organization_id=organization_id,
            location_id=location_id,
            name=name,
            campaign_type=campaign_type.value,
            status=CampaignStatus.DRAFT.value,
            starts_at=starts_at,
            ends_at=ends_at,
            display_rule=display_rule.value,
            display_interval_days=display_interval_days,
            target_networks=target_networks,
            is_skippable=is_skippable,
            created_by=actor_user_id,
        )
        event = CampaignCreated(
            id=campaign.id, organization_id=campaign.organization_id
        )
        logger.info("campaign_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAMPAIGN_CREATED,
            entity_id=campaign.id,
            organization_id=campaign.organization_id,
            description=f"Campaign '{name}' created",
        )
        return campaign

    async def get_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Campaign:
        campaign = await self.repository.get_campaign_by_id(campaign_id)
        if campaign is None:
            raise CampaignNotFoundError(campaign_id)
        if (
            requesting_organization_id is not None
            and campaign.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationCampaignAccessError()
        return campaign

    async def list_campaigns(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Campaign], PaginationMeta]:
        return await self.repository.list_campaigns(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )

    async def update_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> Campaign:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        display_rule = fields.get("display_rule", campaign.display_rule)
        display_interval_days = fields.get(
            "display_interval_days", campaign.display_interval_days
        )
        validate_display_rule_fields(
            DisplayRule(
                display_rule.value
                if isinstance(display_rule, DisplayRule)
                else display_rule
            ),
            display_interval_days,  # type: ignore[arg-type]
        )
        data = {
            key: (
                value.value if isinstance(value, DisplayRule | CampaignType) else value
            )
            for key, value in fields.items()
            if value is not None
        }
        updated = await self.repository.update_campaign(campaign, data)
        event = CampaignUpdated(id=updated.id)
        logger.info("campaign_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAMPAIGN_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Campaign '{updated.name}' updated",
        )
        return updated

    async def delete_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_campaign(campaign)
        event = CampaignDeleted(id=deleted.id, organization_id=deleted.organization_id)
        logger.info("campaign_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAMPAIGN_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Campaign '{deleted.name}' deleted",
        )
        return deleted

    async def clone_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        new_name: str,
    ) -> Campaign:
        """Deep-copies a campaign's own fields plus its ``questions``/
        ``assets`` into a brand-new ``DRAFT`` campaign -- never copies
        ``responses``/``impressions`` (those belong to the original run,
        not the clone). Mirrors ``app.domains.rbac.service
        .RBACService.clone_role``'s own "resolve source, create new row,
        deep-copy child rows" shape."""
        source = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        clone = await self.repository.create_campaign(
            organization_id=source.organization_id,
            location_id=source.location_id,
            name=new_name,
            campaign_type=source.campaign_type,
            status=CampaignStatus.DRAFT.value,
            starts_at=None,
            ends_at=None,
            display_rule=source.display_rule,
            display_interval_days=source.display_interval_days,
            target_networks=list(source.target_networks),
            is_skippable=source.is_skippable,
            created_by=actor_user_id,
        )
        for question in await self.repository.list_questions_for_campaign(source.id):
            await self.repository.create_question(
                campaign_id=clone.id,
                order_index=question.order_index,
                question_text=question.question_text,
                answer_type=question.answer_type,
                options=list(question.options),
                is_required=question.is_required,
                created_by=actor_user_id,
            )
        for asset in await self.repository.list_assets_for_campaign(source.id):
            await self.repository.create_asset(
                campaign_id=clone.id,
                image_url=asset.image_url,
                click_url=asset.click_url,
                alt_text=asset.alt_text,
                locale=asset.locale,
                created_by=actor_user_id,
            )
        await self._audit(
            actor_user_id,
            AuditAction.CAMPAIGN_CLONED,
            entity_id=clone.id,
            organization_id=clone.organization_id,
            description=f"Campaign '{source.name}' cloned as '{new_name}'",
        )
        return clone

    # ========================================================================
    # Lifecycle transitions
    # ========================================================================

    async def _transition_status(
        self,
        campaign_id: uuid.UUID,
        target: CampaignStatus,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        current = CampaignStatus(campaign.status)
        validate_status_transition(current, target)
        updated = await self.repository.update_campaign(
            campaign, {"status": target.value}
        )
        event = CampaignStatusChanged(
            id=updated.id, from_status=current.value, to_status=target.value
        )
        logger.info("campaign_status_changed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAMPAIGN_STATUS_CHANGED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"Campaign '{updated.name}' status: {current.value} -> {target.value}"
            ),
        )
        return updated

    async def schedule_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        if campaign.starts_at is None:
            raise CampaignNotSchedulableError(campaign.id)
        return await self._transition_status(
            campaign_id,
            CampaignStatus.SCHEDULED,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def pause_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        return await self._transition_status(
            campaign_id,
            CampaignStatus.PAUSED,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def resume_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        return await self._transition_status(
            campaign_id,
            CampaignStatus.ACTIVE,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def end_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Campaign:
        return await self._transition_status(
            campaign_id,
            CampaignStatus.ENDED,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def sweep_status_transitions(self) -> int:
        """Keeps the *stored* ``Campaign.status`` reasonably fresh for
        admin dashboards -- called every 5 minutes by ``tasks
        .sweep_campaign_status_transitions``. Never the guest-facing
        source of truth; see ``validators.compute_effective_status`` and
        ``__init__.py``'s own module docstring for why the serving path
        never trusts this stored value alone. Returns the number of
        campaigns transitioned."""
        now = datetime.now(UTC)
        transitioned = 0
        for campaign in await self.repository.list_non_terminal_campaigns():
            current = CampaignStatus(campaign.status)
            effective = compute_effective_status(
                current, starts_at=campaign.starts_at, ends_at=campaign.ends_at, now=now
            )
            if effective == current:
                continue
            await self.repository.update_campaign(campaign, {"status": effective.value})
            transitioned += 1
        return transitioned

    # ========================================================================
    # Questions (SURVEY only)
    # ========================================================================

    async def add_question(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        order_index: int,
        question_text: str,
        answer_type: AnswerType,
        options: list[str],
        is_required: bool,
    ) -> CampaignQuestion:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        if campaign.campaign_type != CampaignType.SURVEY.value:
            raise WrongCampaignTypeError(
                CampaignType.SURVEY.value, campaign.campaign_type
            )
        validate_question_options(answer_type, options)
        return await self.repository.create_question(
            campaign_id=campaign.id,
            order_index=order_index,
            question_text=question_text,
            answer_type=answer_type.value,
            options=options,
            is_required=is_required,
            created_by=actor_user_id,
        )

    async def list_questions(
        self,
        campaign_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[CampaignQuestion]:
        await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_questions_for_campaign(campaign_id)

    async def update_question(
        self,
        question_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> CampaignQuestion:
        question = await self.repository.get_question_by_id(question_id)
        if question is None:
            raise CampaignQuestionNotFoundError(question_id)
        await self.get_campaign(
            question.campaign_id, requesting_organization_id=requesting_organization_id
        )
        answer_type = fields.get("answer_type", question.answer_type)
        options = fields.get("options", question.options)
        validate_question_options(
            AnswerType(
                answer_type.value
                if isinstance(answer_type, AnswerType)
                else answer_type
            ),
            options,  # type: ignore[arg-type]
        )
        data = {
            key: (value.value if isinstance(value, AnswerType) else value)
            for key, value in fields.items()
            if value is not None
        }
        return await self.repository.update_question(question, data)

    async def delete_question(
        self,
        question_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> CampaignQuestion:
        question = await self.repository.get_question_by_id(question_id)
        if question is None:
            raise CampaignQuestionNotFoundError(question_id)
        await self.get_campaign(
            question.campaign_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.soft_delete_question(question)

    # ========================================================================
    # Assets (BANNER/REDIRECT only)
    # ========================================================================

    async def add_asset(
        self,
        campaign_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        image_url: str | None,
        click_url: str | None,
        alt_text: str | None,
        locale: str | None,
    ) -> CampaignAsset:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        if campaign.campaign_type not in (
            CampaignType.BANNER.value,
            CampaignType.REDIRECT.value,
        ):
            raise WrongCampaignTypeError(
                f"{CampaignType.BANNER.value}/{CampaignType.REDIRECT.value}",
                campaign.campaign_type,
            )
        validate_asset_urls(image_url, click_url)
        return await self.repository.create_asset(
            campaign_id=campaign.id,
            image_url=image_url,
            click_url=click_url,
            alt_text=alt_text,
            locale=locale,
            created_by=actor_user_id,
        )

    async def list_assets(
        self,
        campaign_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[CampaignAsset]:
        await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_assets_for_campaign(campaign_id)

    async def update_asset(
        self,
        asset_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> CampaignAsset:
        asset = await self.repository.get_asset_by_id(asset_id)
        if asset is None:
            raise CampaignAssetNotFoundError(asset_id)
        await self.get_campaign(
            asset.campaign_id, requesting_organization_id=requesting_organization_id
        )
        image_url = fields.get("image_url", asset.image_url)
        click_url = fields.get("click_url", asset.click_url)
        validate_asset_urls(image_url, click_url)  # type: ignore[arg-type]
        data = {key: value for key, value in fields.items() if value is not None}
        return await self.repository.update_asset(asset, data)

    async def delete_asset(
        self,
        asset_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> CampaignAsset:
        asset = await self.repository.get_asset_by_id(asset_id)
        if asset is None:
            raise CampaignAssetNotFoundError(asset_id)
        await self.get_campaign(
            asset.campaign_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.soft_delete_asset(asset)

    # ========================================================================
    # Guest-facing: serve / respond / impression
    # ========================================================================

    async def _get_active_guest_session(self, guest_session_id: uuid.UUID) -> object:
        session = await self.guest_session_lookup.get_session_by_id(guest_session_id)
        if session is None:
            raise GuestSessionNotFoundError(guest_session_id)
        if getattr(session, "status", None) != GuestSessionStatus.ACTIVE.value:
            raise GuestSessionNotActiveError(guest_session_id)
        return session

    async def _is_eligible_for_guest(
        self, campaign: Campaign, guest_id: uuid.UUID, now: datetime
    ) -> bool:
        rule = DisplayRule(campaign.display_rule)
        if rule == DisplayRule.EVERY_LOGIN:
            return True
        if rule == DisplayRule.FIRST_LOGIN_ONLY:
            shown = await self.repository.has_guest_been_shown_campaign(
                campaign.id, guest_id
            )
            return not shown
        last_shown_at = await self.repository.get_last_shown_at_for_guest(
            campaign.id, guest_id
        )
        if last_shown_at is None:
            return True
        interval_days = campaign.display_interval_days or DEFAULT_DISPLAY_INTERVAL_DAYS
        return now - last_shown_at >= timedelta(days=interval_days)

    async def get_next_campaign_for_session(
        self, guest_session_id: uuid.UUID
    ) -> NextCampaignResult | None:
        """The core guest-facing resolution: loads the candidate set for
        this session's org/location, keeps only those whose *effective*
        status (``validators.compute_effective_status``) is ``ACTIVE``
        right now, filters by ``target_networks``/``display_rule``
        eligibility, and returns exactly one -- or ``None`` if nothing
        qualifies. Tie-break among multiple eligible campaigns: the one
        with the most recent ``starts_at`` wins (falls back to
        ``created_at`` for org-wide campaigns with no explicit start) --
        a simple, documented policy, not a "smartest" one."""
        session = await self._get_active_guest_session(guest_session_id)
        candidates = await self.repository.list_candidate_campaigns(
            organization_id=session.organization_id, location_id=session.location_id
        )
        now = datetime.now(UTC)
        router_id_str = str(session.router_id)
        eligible: list[Campaign] = []
        for campaign in candidates:
            effective = compute_effective_status(
                CampaignStatus(campaign.status),
                starts_at=campaign.starts_at,
                ends_at=campaign.ends_at,
                now=now,
            )
            if effective != CampaignStatus.ACTIVE:
                continue
            if (
                campaign.target_networks
                and router_id_str not in campaign.target_networks
            ):
                continue
            if not await self._is_eligible_for_guest(campaign, session.guest_id, now):
                continue
            eligible.append(campaign)
        if not eligible:
            return None
        chosen = max(eligible, key=lambda c: c.starts_at or c.created_at)
        questions: list[CampaignQuestion] = []
        asset: CampaignAsset | None = None
        if chosen.campaign_type == CampaignType.SURVEY.value:
            questions = await self.repository.list_questions_for_campaign(chosen.id)
        else:
            assets = await self.repository.list_assets_for_campaign(chosen.id)
            asset = assets[0] if assets else None
        return NextCampaignResult(campaign=chosen, questions=questions, asset=asset)

    async def _get_campaign_for_guest_session(
        self, campaign_id: uuid.UUID, session: object
    ) -> Campaign:
        campaign = await self.repository.get_campaign_by_id(campaign_id)
        if campaign is None or campaign.organization_id != session.organization_id:
            raise CampaignNotFoundError(campaign_id)
        return campaign

    async def submit_response(
        self,
        campaign_id: uuid.UUID,
        *,
        guest_session_id: uuid.UUID,
        answers: dict[str, object],
    ) -> CampaignResponse:
        session = await self._get_active_guest_session(guest_session_id)
        campaign = await self._get_campaign_for_guest_session(campaign_id, session)
        now = datetime.now(UTC)
        effective = compute_effective_status(
            CampaignStatus(campaign.status),
            starts_at=campaign.starts_at,
            ends_at=campaign.ends_at,
            now=now,
        )
        if effective != CampaignStatus.ACTIVE:
            raise CampaignNotActiveError(campaign.id)
        if campaign.campaign_type != CampaignType.SURVEY.value:
            raise WrongCampaignTypeError(
                CampaignType.SURVEY.value, campaign.campaign_type
            )
        if campaign.display_rule == DisplayRule.FIRST_LOGIN_ONLY.value:
            existing = await self.repository.get_response_for_campaign_and_guest(
                campaign.id, session.guest_id
            )
            if existing is not None:
                raise DuplicateFirstLoginResponseError(campaign.id)
        response = await self.repository.create_response(
            campaign_id=campaign.id,
            guest_id=session.guest_id,
            guest_session_id=session.id,
            submitted_at=now,
            answers=answers,
        )
        event = CampaignResponseSubmitted(id=response.id, campaign_id=campaign.id)
        logger.info("campaign_response_submitted", extra=_event_extra(event))
        return response

    async def record_impression(
        self,
        campaign_id: uuid.UUID,
        *,
        guest_session_id: uuid.UUID,
        was_skipped: bool = False,
        was_clicked: bool = False,
    ) -> CampaignImpression:
        session = await self._get_active_guest_session(guest_session_id)
        campaign = await self._get_campaign_for_guest_session(campaign_id, session)
        impression = await self.repository.create_impression(
            campaign_id=campaign.id,
            guest_session_id=session.id,
            shown_at=datetime.now(UTC),
            was_skipped=was_skipped,
            was_clicked=was_clicked,
        )
        event = CampaignImpressionRecorded(
            id=impression.id, campaign_id=campaign.id, was_skipped=was_skipped
        )
        logger.info("campaign_impression_recorded", extra=_event_extra(event))
        return impression

    # ========================================================================
    # Results aggregation / export
    # ========================================================================

    async def get_results(
        self,
        campaign_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> CampaignResults:
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        responses = await self.repository.list_responses_for_campaign(campaign.id)
        impressions = await self.repository.list_impressions_for_campaign(campaign.id)
        breakdowns: list[QuestionResultBreakdown] = []
        if campaign.campaign_type == CampaignType.SURVEY.value:
            questions = await self.repository.list_questions_for_campaign(campaign.id)
            for question in questions:
                raw_answers = [
                    response.answers[str(question.id)]
                    for response in responses
                    if str(question.id) in response.answers
                ]
                breakdowns.append(_build_question_breakdown(question, raw_answers))
        return CampaignResults(
            campaign_id=campaign.id,
            total_responses=len(responses),
            total_impressions=len(impressions),
            total_skipped=sum(1 for i in impressions if i.was_skipped),
            total_clicked=sum(1 for i in impressions if i.was_clicked),
            question_breakdowns=breakdowns,
        )

    async def export_results_csv(
        self,
        campaign_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> str:
        """Non-paginated CSV of every ``CampaignResponse`` for this
        campaign. Guest identity columns are masked by default, exactly
        like every other guest-PII surface (see ``app.common.masking``'s
        own module docstring) -- built by round-tripping each row through
        ``_ResultsExportRow`` rather than hand-rolling the masking-flag
        check here, so this path can never silently drift from the
        Pydantic-serialized JSON path's own masking/audit behavior."""
        campaign = await self.get_campaign(
            campaign_id, requesting_organization_id=requesting_organization_id
        )
        responses = await self.repository.list_responses_for_campaign(campaign.id)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["guest_identifier", "guest_name", "submitted_at", "answers"])
        for response in responses:
            guest = await self.guest_session_lookup.get_guest_by_id(response.guest_id)
            identifier = getattr(guest, "identifier", None)
            display_name = getattr(guest, "display_name", None)
            row = _ResultsExportRow(
                guest_identifier=identifier, guest_name=display_name
            )
            dumped = row.model_dump()
            writer.writerow(
                [
                    dumped["guest_identifier"] or "",
                    dumped["guest_name"] or "",
                    response.submitted_at.isoformat(),
                    response.answers,
                ]
            )
        return buffer.getvalue()

    # ========================================================================
    # Internal
    # ========================================================================

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="campaign",
            entity_id=entity_id,
            organization_id=organization_id,
            description=description,
        )


def _build_question_breakdown(
    question: CampaignQuestion, raw_answers: list[object]
) -> QuestionResultBreakdown:
    answer_type = AnswerType(question.answer_type)
    option_counts: dict[str, int] | None = None
    average_rating: float | None = None
    rating_distribution: dict[int, int] | None = None
    free_text_answers: list[str] | None = None

    if answer_type == AnswerType.SINGLE_CHOICE:
        option_counts = dict(Counter(a for a in raw_answers if isinstance(a, str)))
    elif answer_type == AnswerType.MULTI_CHOICE:
        counter: Counter[str] = Counter()
        for answer in raw_answers:
            if isinstance(answer, list):
                counter.update(str(item) for item in answer)
        option_counts = dict(counter)
    elif answer_type == AnswerType.RATING_5:
        ratings = [int(a) for a in raw_answers if isinstance(a, int | float)]
        rating_distribution = dict(Counter(ratings))
        average_rating = sum(ratings) / len(ratings) if ratings else None
    else:
        free_text_answers = [str(a) for a in raw_answers if a]

    return QuestionResultBreakdown(
        question_id=question.id,
        question_text=question.question_text,
        answer_type=question.answer_type,
        total_answers=len(raw_answers),
        option_counts=option_counts,
        average_rating=average_rating,
        rating_distribution=rating_distribution,
        free_text_answers=free_text_answers,
    )


__all__ = [
    "CampaignsService",
    "NextCampaignResult",
    "QuestionResultBreakdown",
    "CampaignResults",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "GuestSessionLookupProtocol",
    "AuditLogWriter",
]

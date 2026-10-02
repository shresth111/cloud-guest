"""Guest Marketing business logic (contract §5, sending mechanics §9).

## Tenant and location scoping

Every public method takes a :class:`CallerScope`. ``organization_id`` comes
only from ``RequireOrganization`` (never a body or query), and every
repository read filters on it. ``location_id`` is the caller's location
confinement (contract §5.0 "LocScope"):

* A caller who sends ``X-Location-Id`` -- or whose grants confine them to
  locations (``CallerLocationScope``) -- is location-scoped. Any location id
  they name must be omitted, null, or their own; an omitted/null one is
  rewritten to their own, **never** read as "all" (the null-means-all bug
  class the spec calls out in ``enforce_target_location``).
* They see only campaigns whose ``location_id`` is theirs. An org-wide
  campaign is a 404 to them, not a 403, so its existence does not leak.
* They see only guests who have a session at their location.

## No fake success

Nothing is stored as submitted without a provider response, and a channel
whose marketing sender is not configured (including "logging" mode) is an
explicit 409 ``channel_not_configured`` at schedule/test-send time and an
honest ``configured: false`` on ``/marketing/status``.
"""

from __future__ import annotations

import asyncio
import html
import logging
import time as time_module
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from app.core.config import Settings
from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.enums import AuditAction

from .constants import (
    ACTIVE_CAMPAIGN_STATUSES,
    AUDIENCE_SAMPLE_SIZE,
    CAMPAIGN_VARIABLE_MAX_LENGTHS,
    CHANNEL_ORDER,
    CONSENT_STATUS_NONE,
    DEFAULT_CONSENT_TEXT,
    DEFAULT_CONSENT_TEXT_VERSION,
    EMAIL_MAX_BODY_BYTES,
    GUEST_NAME_FALLBACK,
    QUIET_HOURS_CHANNELS,
    RECIPIENT_ADDRESS_RETENTION_DAYS,
    SAMPLE_GUEST_NAME,
    SAMPLE_UNSUBSCRIBE_TOKEN,
    SCHEDULE_IDEMPOTENCY_WINDOW_HOURS,
    SCHEDULE_MAX_LEAD_DAYS,
    SCHEDULE_MIN_LEAD_MINUTES,
    SEND_BATCH_SIZE,
    SEND_MAX_ATTEMPTS,
    STALE_SENDING_MINUTES,
    TEMPLATE_VARIABLES,
    TEST_SEND_COUNTER_KEY_TEMPLATE,
    WORST_CASE_VARIABLE_LENGTHS,
    CampaignStatus,
    CancelReason,
    Channel,
    ChannelMode,
    ConsentSource,
    ConsentStatus,
    RecipientStatus,
    SendableReason,
    SkipReason,
    SuppressionReason,
    TemplateCategory,
    WhatsAppApprovalStatus,
)
from .credits import (
    CampaignCredits,
    actual_units,
    per_recipient_minor,
)
from .exceptions import (
    AudienceEmptyError,
    AudienceTooLargeError,
    ChannelMismatchError,
    ChannelMissingInTemplateError,
    ChannelNotConfiguredError,
    ConsentNotOfferedError,
    CrossLocationError,
    DailyTestSendLimitError,
    InvalidAddressError,
    InvalidStatusTransitionError,
    InvalidTokenError,
    LocationNotFoundForMarketingError,
    MarketingError,
    MarketingNotFoundError,
    MarketingValidationError,
    OwnProviderUnacknowledgedError,
    PortalConfigMissingError,
    QuietHoursError,
    ScheduleOutOfRangeError,
    SessionNotActiveError,
    SmsTooLongError,
    StaleConsentTextError,
    SyncedTemplateReadOnlyError,
    SystemTemplateReadOnlyError,
    TemplateEmptyError,
    TemplateInUseError,
    TemplateNameTakenError,
    TemplateNotFoundError,
    TemplateNotSendableError,
    UnknownVariableError,
    UnsubscribeLinkMissingError,
    VersionConflictError,
    WhatsAppCustomNotSupportedError,
)
from .models import MarketingCampaign, MarketingCampaignRecipient, MarketingTemplate
from .providers import (
    OwnSenders,
    build_own_senders,
    decrypt_config,
    placeholder_count,
    scrub,
    spec_for,
)
from .repository import (
    AudienceCandidate,
    AudienceCriteria,
    MarketingRepository,
    new_unsubscribe_token,
)
from .schemas import (
    AudienceFilter,
    CampaignCreate,
    CampaignUpdate,
    PortalConsentUpdate,
    TemplateCreate,
    TemplatePreviewRequest,
    TemplateUpdate,
)
from .senders import ChannelStatus, MarketingSenders, ProviderResult, SendError
from .validators import (
    TemplateVariableError,
    bound_values,
    clean_email_html,
    derive_address,
    extract_variables,
    in_quiet_hours,
    mask_address,
    next_allowed_at,
    normalize_address,
    organization_zone,
    render,
    sms_body_problems,
    sms_stats,
    utc_iso,
)

logger = logging.getLogger(__name__)

_EXCLUSION_KEYS = (
    "no_consent",
    "opted_out",
    "suppressed",
    "no_address",
    "invalid_address",
    "blocked",
)


# The system email wrapper (spec §6): venue header, the template body, and a
# footer with the venue name, location address and unsubscribe link.
_EMAIL_LAYOUT = (
    '<!doctype html><html><body style="margin:0;padding:0;background:#f5f5f7;">'
    '<span style="display:none;max-height:0;overflow:hidden;">{preheader}</span>'
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
    '<tr><td align="center" style="padding:24px 12px;">'
    '<table role="presentation" width="600" style="max-width:600px;'
    "background:#ffffff;border-radius:8px;font-family:Arial,Helvetica,sans-serif;"
    'font-size:15px;line-height:22px;color:#1f2937;">'
    '<tr><td style="padding:20px 24px;font-size:18px;font-weight:bold;">'
    "{venue}</td></tr>"
    '<tr><td style="padding:0 24px 16px 24px;">{body}</td></tr>'
    '<tr><td style="padding:16px 24px;font-size:12px;color:#6b7280;'
    'border-top:1px solid #e5e7eb;">{venue}{footer_address}<br>'
    "You received this because you opted in on {venue}'s WiFi. "
    '<a href="{link}">Unsubscribe</a></td></tr>'
    "</table></td></tr></table></body></html>"
)


OWN_PROVIDER_REQUIRES_OWN_TEMPLATE = "own_provider_requires_own_template"


def _campaign_provider(campaign: Any, rows: dict[uuid.UUID, Any]) -> dict | None:
    """Campaign.provider (spec §12.4): null for drafts, else the snapshot."""
    if campaign.status == CampaignStatus.DRAFT.value:
        return None
    source = getattr(campaign, "provider_source", None) or "wyfy"
    if source != "own":
        return {"source": "wyfy", "type": None, "display_name": "Wyfy default"}
    row = rows.get(getattr(campaign, "org_provider_id", None))
    provider_type = getattr(campaign, "provider_type", None)
    if row is not None:
        name = provider_display_name(row)
    else:
        spec = spec_for(Channel(campaign.channel), provider_type or "")
        name = f"Your {spec.display_name if spec else provider_type} (removed)"
    return {"source": "own", "type": provider_type, "display_name": name}


def _campaign_credits(
    campaign: Any, totals: tuple[int, int, int] | None
) -> dict[str, Any] | None:
    """Campaign.credits (spec §13.7): null for drafts and own-provider
    campaigns; otherwise the frozen price and the gross ledger totals."""
    snapshot = getattr(campaign, "price_snapshot", None)
    if (
        campaign.status == CampaignStatus.DRAFT.value
        or getattr(campaign, "provider_source", "wyfy") == "own"
        or not snapshot
    ):
        return None
    reserved, debited, released = totals or (0, 0, 0)
    return {
        "price_snapshot": {
            "channel": snapshot.get("channel"),
            "unit": snapshot.get("unit"),
            "unit_price_minor": snapshot.get("unit_price_minor"),
        },
        "reserved_minor": reserved,
        "debited_minor": debited,
        "released_minor": released,
    }


def _own_status(channel: Channel, row: Any) -> ChannelStatus:
    return ChannelStatus(
        channel,
        True,
        row.provider_type,
        ChannelMode.LIVE,
        None,
        requires_dlt_template_id=channel is Channel.SMS,
        custom_templates_supported=channel is not Channel.WHATSAPP,
    )


def render_positional(body: str | None, parameters: list[str]) -> str:
    """Preview of a WABA template: ``{{n}}`` -> parameters[n-1]."""
    import re as _re

    def _sub(match):  # noqa: ANN001
        index = int(match.group(1)) - 1
        return parameters[index] if 0 <= index < len(parameters) else ""

    return _re.sub(r"\{\{(\d+)\}\}", _sub, body or "")


class _OwnProviderTripped(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class ProviderResolution:
    """The §12.1 answer for one channel, right now."""

    channel: Channel
    source: str  # "wyfy" | "own"
    row: Any | None
    status: ChannelStatus
    byo_entitled: bool

    @property
    def own(self) -> bool:
        return self.source == "own"

    @property
    def needs_fallback_ack(self) -> bool:
        """The org HAS an own row for the channel that is not what will be
        used (enabled but unverified, failed, or BYO locked): scheduling
        through Wyfy then needs an explicit acknowledgement (Q11 = A)."""
        row = self.row
        return (
            row is not None
            and not self.own
            and (bool(row.enabled) or row.status == "failed")
        )

    def display_name(self) -> str:
        if not self.own or self.row is None:
            return "Wyfy default"
        return provider_display_name(self.row)

    def as_status_dict(self) -> dict[str, Any]:
        data = self.status.as_dict()
        data["provider_source"] = self.source
        data["provider_display_name"] = self.display_name()
        data["own_provider_status"] = self.row.status if self.row is not None else None
        # Additive (FE request, 2026-09-26): with own_provider_status this is
        # everything the composer needs to know that acknowledge_wyfy_fallback
        # will be required (see needs_fallback_ack / deviation #20).
        data["own_provider_enabled"] = (
            bool(self.row.enabled) if self.row is not None else None
        )
        data["requires_fallback_ack"] = self.needs_fallback_ack
        data["byo_entitled"] = self.byo_entitled
        return data


def provider_display_name(row: Any) -> str:
    spec = spec_for(Channel(row.channel), row.provider_type)
    label = provider_sender_label(row)
    name = spec.display_name if spec else row.provider_type
    return f"Your {name} ({label})" if label else f"Your {name}"


def provider_sender_label(row: Any) -> str | None:
    spec = spec_for(Channel(row.channel), row.provider_type)
    display = row.display or {}
    if spec is None or spec.sender_field is None:
        return None
    value = display.get(spec.sender_field)
    return value if isinstance(value, str) else None


def default_own_sender_factory(row: Any, settings: Settings) -> OwnSenders:
    config = decrypt_config(row.config_encrypted, settings=settings)
    senders = build_own_senders(row.provider_type, config, settings=settings)
    senders.scrubber = lambda message: scrub(message, config)
    return senders


@dataclass(frozen=True)
class CallerScope:
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None


class RateLimiter:
    """Per-channel pacing, shared across workers through Redis
    (``marketing:rate:{channel}:{second}``). With no Redis (unit tests) it
    only paces locally."""

    def __init__(self, redis: Any | None, rates: dict[Channel, float]) -> None:
        self.redis = redis
        self.rates = rates

    async def acquire(
        self,
        channel: Channel,
        *,
        own_organization_id: uuid.UUID | None = None,
        own_rate: float = 5.0,
    ) -> None:
        """An own provider gets its own per-organization bucket
        (``marketing:rate:{channel}:org:{org_id}``) so Wyfy's shared bucket
        never throttles a venue that pays its own provider (spec §12.5)."""
        if own_organization_id is not None:
            limit = max(int(own_rate), 1)
            prefix = f"marketing:rate:{channel.value}:org:{own_organization_id}"
        else:
            limit = max(int(self.rates.get(channel, 10.0)), 1)
            prefix = f"marketing:rate:{channel.value}"
        if self.redis is None:
            return
        while True:
            second = int(time_module.time())
            key = f"{prefix}:{second}"
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, 2)
            if count <= limit:
                return
            await asyncio.sleep(max(0.0, (second + 1) - time_module.time()) + 0.01)


class MarketingService:
    def __init__(
        self,
        repository: MarketingRepository,
        *,
        settings: Settings,
        senders: MarketingSenders,
        redis: Any | None = None,
        audit_writer: Any | None = None,
        entitlement_check: Callable[[uuid.UUID], Awaitable[bool]] | None = None,
        enqueue_batch: Callable[[uuid.UUID, int], None] | None = None,
        now: Callable[[], datetime] | None = None,
        caller_location_scope: frozenset[uuid.UUID] | None = None,
        byo_entitlement_check: Callable[[uuid.UUID], Awaitable[bool]] | None = None,
        own_sender_factory: Callable[[Any], OwnSenders] | None = None,
        credits: CampaignCredits | None = None,
    ) -> None:
        self.repository = repository
        # Spec §13 charge flow. None only in tests that predate credits; every
        # production wiring (API dependencies and the Celery tasks) passes it.
        self.credits = credits
        # guest_marketing_byo (spec §12.1). None = not entitled.
        self.byo_entitlement_check = byo_entitlement_check
        # Builds the adapters for one own-provider row; decrypts in-process.
        self.own_sender_factory = own_sender_factory or (
            lambda row: default_own_sender_factory(row, settings)
        )
        # Grant-derived confinement (``CallerLocationScope``). ``get_caller_scope``
        # already folds it into ``CallerScope.location_id``; ``_guard``
        # re-asserts it at every entry point so a CallerScope built any other
        # way cannot widen a confined caller.
        self.caller_location_scope = caller_location_scope
        self.settings = settings
        self.senders = senders
        self.redis = redis
        self.audit_writer = audit_writer
        self.entitlement_check = entitlement_check
        self.enqueue_batch = enqueue_batch
        self._now = now or (lambda: datetime.now(UTC))
        self.rate_limiter = RateLimiter(
            redis,
            {
                Channel.SMS: settings.marketing_rate_per_sec_sms,
                Channel.WHATSAPP: settings.marketing_rate_per_sec_whatsapp,
                Channel.EMAIL: settings.marketing_rate_per_sec_email,
            },
        )

    # ======================================================================
    # Scope helpers
    # ======================================================================

    def _guard(self, scope: CallerScope) -> None:
        confinement = self.caller_location_scope
        if confinement is None:
            return
        if scope.location_id is None or scope.location_id not in confinement:
            raise CrossLocationError("You can only act on your own location.")

    async def _require_location(self, scope: CallerScope, location_id: uuid.UUID):
        location = await self.repository.get_location(
            scope.organization_id, location_id
        )
        if location is None:
            raise LocationNotFoundForMarketingError(
                f"Location not found: {location_id}"
            )
        return location

    async def resolve_location_ids(
        self, scope: CallerScope, requested: list[uuid.UUID] | None
    ) -> list[uuid.UUID] | None:
        """Contract §5.0 rules 1 and 3. ``None`` = every org location
        (org-scoped callers only)."""
        self._guard(scope)
        if scope.location_id is not None:
            if requested and any(item != scope.location_id for item in requested):
                raise CrossLocationError("You can only target your own location.")
            return [scope.location_id]
        if not requested:
            return None
        unique = list(dict.fromkeys(requested))
        for location_id in unique:
            await self._require_location(scope, location_id)
        return unique

    async def resolve_single_location(
        self, scope: CallerScope, requested: uuid.UUID | None
    ) -> uuid.UUID | None:
        self._guard(scope)
        if scope.location_id is not None:
            if requested is not None and requested != scope.location_id:
                raise CrossLocationError("You can only target your own location.")
            return scope.location_id
        if requested is not None:
            await self._require_location(scope, requested)
        return requested

    async def _organization(self, organization_id: uuid.UUID):
        organization = await self.repository.get_organization(organization_id)
        if organization is None:
            raise MarketingNotFoundError("Organization not found")
        return organization

    def _zone(self, organization):
        return organization_zone(getattr(organization, "timezone", None))

    async def _audit(
        self,
        scope: CallerScope | None,
        action: AuditAction,
        *,
        entity_type: str,
        entity_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        description: str,
        metadata: dict[str, Any] | None = None,
        location_id: uuid.UUID | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=scope.actor_user_id if scope else None,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            organization_id=organization_id,
            location_id=location_id,
            description=description,
            event_metadata=metadata or {},
        )

    # ======================================================================
    # Status / settings (§5.1)
    # ======================================================================

    def channel_statuses(self) -> list[ChannelStatus]:
        return [self.senders.status(channel) for channel in CHANNEL_ORDER]

    # -- provider resolution (spec §12.1) ----------------------------------

    async def _byo_entitled(self, organization_id: uuid.UUID) -> bool:
        if self.byo_entitlement_check is None:
            return False
        try:
            return await self.byo_entitlement_check(organization_id)
        except Exception:  # noqa: BLE001 - no licence row etc. = not entitled
            logger.info("marketing_byo_entitlement_check_failed", exc_info=True)
            return False

    async def resolve_providers(
        self, organization_id: uuid.UUID
    ) -> dict[Channel, ProviderResolution]:
        """effective(org, channel) = own iff a row exists, is enabled, is
        verified and the org is entitled to guest_marketing_byo; else Wyfy."""
        rows = await self.repository.list_providers(organization_id)
        byo = await self._byo_entitled(organization_id)
        out: dict[Channel, ProviderResolution] = {}
        for channel in CHANNEL_ORDER:
            row = rows.get(channel.value)
            effective = bool(
                row is not None and row.enabled and row.status == "verified" and byo
            )
            if effective:
                status = ChannelStatus(
                    channel,
                    True,
                    row.provider_type,
                    ChannelMode.LIVE,
                    None,
                    requires_dlt_template_id=channel is Channel.SMS,
                    custom_templates_supported=channel is not Channel.WHATSAPP,
                )
            else:
                status = self.senders.status(channel)
            out[channel] = ProviderResolution(
                channel=channel,
                source="own" if effective else "wyfy",
                row=row,
                status=status,
                byo_entitled=byo,
            )
        return out

    @staticmethod
    def _consent_view(config, venue_name: str) -> dict[str, Any]:
        if config is None:
            return {
                "enabled": False,
                "text": DEFAULT_CONSENT_TEXT.format(venue_name=venue_name),
                "text_version": DEFAULT_CONSENT_TEXT_VERSION,
            }
        text = config.marketing_consent_text or DEFAULT_CONSENT_TEXT.format(
            venue_name=venue_name
        )
        return {
            "enabled": bool(config.marketing_consent_enabled),
            "text": text,
            "text_version": config.marketing_consent_text_version
            or DEFAULT_CONSENT_TEXT_VERSION,
        }

    async def status(self, scope: CallerScope) -> dict[str, Any]:
        self._guard(scope)
        organization = await self._organization(scope.organization_id)
        config = await self.repository.get_portal_config(
            scope.organization_id, scope.location_id
        )
        location_ids = [scope.location_id] if scope.location_id else None
        counts = await self.repository.consent_counts(
            scope.organization_id, location_ids
        )
        zone = self._zone(organization)
        resolutions = await self.resolve_providers(scope.organization_id)
        return {
            "channels": [
                resolutions[channel].as_status_dict() for channel in CHANNEL_ORDER
            ],
            "portal_consent": self._consent_view(config, organization.name),
            "consent_counts": {
                channel.value: counts.get(channel.value, 0) for channel in CHANNEL_ORDER
            },
            "quiet_hours": {
                "start": self.settings.marketing_quiet_hours_start,
                "end": self.settings.marketing_quiet_hours_end,
                "timezone": zone.key,
                "applies_to": [channel.value for channel in QUIET_HOURS_CHANNELS],
            },
            "limits": {
                "max_recipients_per_campaign": (
                    self.settings.marketing_max_recipients_per_campaign
                ),
                "test_sends_per_day": self.settings.marketing_test_sends_per_day,
            },
            # Characters the SMS counter must budget for {{unsubscribe_link}}:
            # max(30, the real link length), the same figure the server's
            # sms_too_long check uses (contract change 2026-09-25).
            "sms_unsubscribe_link_budget": self.sms_unsubscribe_link_budget(),
        }

    def sms_unsubscribe_link_budget(self) -> int:
        return max(
            WORST_CASE_VARIABLE_LENGTHS["unsubscribe_link"],
            len(self._unsubscribe_link(new_unsubscribe_token())),
        )

    async def update_portal_consent(
        self, scope: CallerScope, body: PortalConsentUpdate
    ) -> dict[str, Any]:
        location_id = await self.resolve_single_location(scope, body.location_id)
        assert location_id is not None
        organization = await self._organization(scope.organization_id)
        config = await self.repository.get_portal_config(
            scope.organization_id, location_id
        )
        if config is None:
            raise PortalConfigMissingError(
                "No captive portal is configured for this location yet."
            )
        if config.location_id is None and scope.location_id is not None:
            # The venue is served by the organization's shared default portal.
            # Changing it would change every venue it serves -- not a
            # location-scoped caller's decision to make.
            raise PortalConfigMissingError(
                "This venue uses the organization's shared portal; an "
                "organization admin must change its opt-in."
            )
        data: dict[str, Any] = {"marketing_consent_enabled": body.enabled}
        current_version = config.marketing_consent_text_version
        # Only touch the wording when the request names it: an omitted
        # `text` must not wipe a custom wording or bump the version (each
        # consent row records the version the guest agreed to). An explicit
        # null resets to the default wording, which is a new version.
        text_changed = False
        if "text" in body.model_fields_set:
            new_text = body.text.strip() if body.text else None
            if new_text != config.marketing_consent_text:
                data["marketing_consent_text"] = new_text
                text_changed = True
        if text_changed or current_version is None:
            # An unset version means the default wording (v1) was in effect.
            data["marketing_consent_text_version"] = (
                _bump_version(current_version or DEFAULT_CONSENT_TEXT_VERSION)
                if text_changed
                else DEFAULT_CONSENT_TEXT_VERSION
            )
        await self.repository.update_portal_config(config, data)
        await self._audit(
            scope,
            AuditAction.MARKETING_PORTAL_CONSENT_UPDATED,
            entity_type="captive_portal_config",
            entity_id=config.id,
            organization_id=scope.organization_id,
            location_id=location_id,
            description=f"Marketing opt-in {'enabled' if body.enabled else 'disabled'}",
            metadata={
                "enabled": body.enabled,
                "text_version": config.marketing_consent_text_version,
            },
        )
        view = self._consent_view(config, organization.name)
        return {"location_id": str(location_id), **view}

    # ======================================================================
    # Contacts + staff opt-out (§5.2)
    # ======================================================================

    async def list_contacts(
        self,
        scope: CallerScope,
        *,
        channel: Channel,
        consent_status: str,
        location_id: uuid.UUID | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        if consent_status not in {
            ConsentStatus.OPTED_IN.value,
            ConsentStatus.OPTED_OUT.value,
            CONSENT_STATUS_NONE,
        }:
            raise MarketingValidationError(
                "consent_status must be opted_in, opted_out or none"
            )
        location_ids = await self.resolve_location_ids(
            scope, [location_id] if location_id else None
        )
        rows, meta = await self.repository.list_contacts(
            organization_id=scope.organization_id,
            channel=channel.value,
            consent_status=consent_status,
            location_ids=location_ids,
            search=search,
            page=page,
            page_size=page_size,
        )
        items = []
        for guest, consent in rows:
            address = derive_address(
                channel, identifier=guest.identifier, email=guest.email
            )
            items.append(
                {
                    "guest_id": str(guest.id),
                    "display_name": guest.display_name,
                    "masked_address": mask_address(channel, address.address)
                    if address.address
                    else None,
                    "consent_status": consent.status
                    if consent
                    else CONSENT_STATUS_NONE,
                    "consent_source": consent.source if consent else None,
                    "consent_changed_at": utc_iso(consent.status_changed_at)
                    if consent
                    else None,
                    "last_seen_at": utc_iso(guest.last_seen_at),
                    "total_visit_count": guest.total_visit_count,
                }
            )
        return items, meta

    async def _visible_guest(self, scope: CallerScope, guest_id: uuid.UUID):
        self._guard(scope)
        guest = await self.repository.get_guest(scope.organization_id, guest_id)
        if guest is None:
            raise MarketingNotFoundError("Guest not found")
        if (
            scope.location_id is not None
            and not await self.repository.guest_visited_location(
                guest.id, scope.location_id
            )
        ):
            raise MarketingNotFoundError("Guest not found")
        return guest

    async def staff_opt_out(
        self,
        scope: CallerScope,
        guest_id: uuid.UUID,
        channels: list[Channel],
        note: str | None,
    ) -> dict[str, Any]:
        guest = await self._visible_guest(scope, guest_id)
        now = self._now()
        result: dict[str, str] = {}
        for channel in dict.fromkeys(channels):
            await self._opt_out(
                organization_id=scope.organization_id,
                guest=guest,
                channel=channel,
                source=ConsentSource.STAFF_RECORDED,
                reason=SuppressionReason.STAFF_RECORDED,
                actor_user_id=scope.actor_user_id,
                ip_address=None,
                location_id=scope.location_id,
                now=now,
            )
            result[channel.value] = ConsentStatus.OPTED_OUT.value
        await self._audit(
            scope,
            AuditAction.MARKETING_CONSENT_STAFF_OPT_OUT,
            entity_type="guest",
            entity_id=guest.id,
            organization_id=scope.organization_id,
            location_id=scope.location_id,
            description="Staff recorded a marketing opt-out",
            metadata={"channels": list(result), "note": note},
        )
        return {"guest_id": str(guest.id), "channels": result}

    async def _opt_out(
        self,
        *,
        organization_id: uuid.UUID,
        guest,
        channel: Channel,
        source: ConsentSource,
        reason: SuppressionReason,
        actor_user_id: uuid.UUID | None,
        ip_address: str | None,
        location_id: uuid.UUID | None,
        now: datetime,
        address_override: str | None = None,
        source_recipient_id: uuid.UUID | None = None,
    ) -> None:
        """Consent row + consent event + suppression, in the caller's
        transaction. Idempotent."""
        if guest is not None:
            await self.repository.upsert_consent(
                organization_id=organization_id,
                guest_id=guest.id,
                channel=channel.value,
                status=ConsentStatus.OPTED_OUT.value,
                source=source.value,
                consent_text_version=None,
                location_id=location_id,
                ip_address=ip_address,
                actor_user_id=actor_user_id,
                now=now,
            )
        address = address_override
        if address is None and guest is not None:
            address = derive_address(
                channel, identifier=guest.identifier, email=guest.email
            ).address
        if address:
            await self.repository.add_suppression(
                organization_id=organization_id,
                channel=channel.value,
                address_normalized=address,
                reason=reason.value,
                source_recipient_id=source_recipient_id,
            )

    # ======================================================================
    # Audience (§5.3)
    # ======================================================================

    async def _criteria(
        self, scope: CallerScope, audience: AudienceFilter, organization
    ) -> AudienceCriteria:
        location_ids = await self.resolve_location_ids(scope, audience.location_ids)
        zone = self._zone(organization)

        def _start_of(day: date) -> datetime:
            return datetime(day.year, day.month, day.day, tzinfo=zone).astimezone(UTC)

        now = self._now()
        return AudienceCriteria(
            organization_id=scope.organization_id,
            channel=audience.channel.value,
            location_ids=location_ids,
            visited_from=_start_of(audience.visited_from)
            if audience.visited_from
            else None,
            visited_before=_start_of(audience.visited_to + timedelta(days=1))
            if audience.visited_to
            else None,
            min_visits=audience.min_visits,
            max_visits=audience.max_visits,
            last_seen_before=now - timedelta(days=audience.not_seen_for_days)
            if audience.not_seen_for_days
            else None,
            require_name=audience.require_name,
        )

    async def evaluate_audience(
        self, scope: CallerScope, audience: AudienceFilter
    ) -> tuple[dict[str, Any], list[tuple[AudienceCandidate, str]]]:
        """The preview object and the reachable ``(guest, address)`` list,
        ordered by ``last_seen_at`` desc. Exclusion precedence (each guest
        counted once): no_consent, opted_out, blocked, no_address,
        invalid_address, suppressed."""
        organization = await self._organization(scope.organization_id)
        criteria = await self._criteria(scope, audience, organization)
        counts = await self.repository.audience(criteria)
        channel = audience.channel
        excluded = dict.fromkeys(_EXCLUSION_KEYS, 0)
        excluded["no_consent"] = counts.no_consent
        excluded["opted_out"] = counts.opted_out
        with_address: list[tuple[AudienceCandidate, str]] = []
        for candidate in counts.opted_in:
            if candidate.is_blocked:
                excluded["blocked"] += 1
                continue
            result = derive_address(
                channel, identifier=candidate.identifier, email=candidate.email
            )
            if result.address is None:
                excluded[result.problem or "no_address"] += 1
                continue
            with_address.append((candidate, result.address))
        suppressed = await self.repository.suppressed_addresses(
            scope.organization_id,
            channel.value,
            [address for _, address in with_address],
        )
        reachable = []
        for candidate, address in with_address:
            if address in suppressed:
                excluded["suppressed"] += 1
                continue
            reachable.append((candidate, address))
        limit = self.settings.marketing_max_recipients_per_campaign
        preview = {
            "channel": channel.value,
            "matched_guests": counts.matched,
            "reachable": len(reachable),
            "excluded": excluded,
            "capped": len(reachable) > limit,
            "sample": [
                {
                    "guest_id": str(candidate.guest_id),
                    "display_name": candidate.display_name,
                    "masked_address": mask_address(channel, address),
                    "last_seen_at": utc_iso(candidate.last_seen_at),
                    "total_visit_count": candidate.total_visit_count,
                }
                for candidate, address in reachable[:AUDIENCE_SAMPLE_SIZE]
            ],
        }
        return preview, reachable

    async def audience_preview(
        self, scope: CallerScope, audience: AudienceFilter
    ) -> dict[str, Any]:
        preview, _ = await self.evaluate_audience(scope, audience)
        preview["credit_estimate"] = await self._credit_estimate(
            scope.organization_id, audience.channel
        )
        return preview

    async def _credit_estimate(
        self, organization_id: uuid.UUID, channel: Channel
    ) -> dict[str, Any] | None:
        """§13.7: per recipient per unit only (a preview has no template, so
        no segment count). Own provider = 0."""
        if self.credits is None:
            return None
        resolution = (await self.resolve_providers(organization_id))[channel]
        if resolution.own:
            quote_price, unit = 0, None
        else:
            quote = (await self.credits.prices.quotes(organization_id))[channel]
            quote_price, unit = quote.unit_price_minor, quote.unit
        from .credits import UNIT_BY_CHANNEL

        return {
            "provider_source": resolution.source,
            "unit": unit or UNIT_BY_CHANNEL[channel],
            "unit_price_minor": quote_price,
            "estimated_minor_per_unit_recipient": quote_price,
        }

    async def estimate(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> dict[str, Any]:
        """``GET /marketing/campaigns/{id}/estimate`` (§13.7): what schedule
        would reserve now. A draft is priced live (current provider, current
        price); a scheduled or sent campaign at its own snapshot."""
        campaign = await self._get_campaign(scope, campaign_id)
        channel = Channel(campaign.channel)
        audience = AudienceFilter.model_validate(campaign.audience_filter)
        preview, _ = await self.evaluate_audience(scope, audience)
        reachable = min(
            preview["reachable"], self.settings.marketing_max_recipients_per_campaign
        )
        available = (
            await self.credits.available_minor(scope.organization_id)
            if self.credits is not None
            else 0
        )
        if campaign.status == CampaignStatus.DRAFT.value:
            resolution = (await self.resolve_providers(scope.organization_id))[channel]
            source = resolution.source
            price_snapshot = None
            if not resolution.own and self.credits is not None:
                template = await self._get_template(scope, campaign.template_id)
                snapshot = await self._build_snapshot(campaign, template)
                price_snapshot = await self.credits.quote(
                    scope.organization_id,
                    channel,
                    snapshot,
                    unsubscribe_link_budget=self.sms_unsubscribe_link_budget(),
                )
        else:
            source = getattr(campaign, "provider_source", "wyfy") or "wyfy"
            price_snapshot = getattr(campaign, "price_snapshot", None)
        from .credits import UNIT_BY_CHANNEL

        if source == "own" or price_snapshot is None:
            return {
                "provider_source": source,
                "reachable": reachable,
                "unit": UNIT_BY_CHANNEL[channel],
                "unit_price_minor": 0,
                "units_per_recipient_max": 0,
                "estimated_max_minor": 0,
                "available_minor": available,
                "sufficient": True,
            }
        needed = reachable * per_recipient_minor(price_snapshot)
        return {
            "provider_source": source,
            "reachable": reachable,
            "unit": price_snapshot["unit"],
            "unit_price_minor": price_snapshot["unit_price_minor"],
            "units_per_recipient_max": price_snapshot["units_per_recipient_max"],
            "estimated_max_minor": needed,
            "available_minor": available,
            "sufficient": available >= needed,
        }

    # ======================================================================
    # Templates (§5.4)
    # ======================================================================

    async def _review_url(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> str | None:
        config = await self.repository.get_portal_config(organization_id, location_id)
        return getattr(config, "review_url", None) if config else None

    def _sendable_for(
        self,
        template: MarketingTemplate | dict[str, Any],
        channel: Channel,
        *,
        review_url: str | None,
        resolution: ProviderResolution | None = None,
    ) -> tuple[bool, str | None]:
        get = (
            template.get
            if isinstance(template, dict)
            else lambda key: getattr(template, key, None)
        )
        body_key = {
            Channel.SMS: "sms_body",
            Channel.WHATSAPP: "whatsapp_body",
            Channel.EMAIL: "email_body_html",
        }[channel]
        body = get(body_key)
        if not body:
            return False, SendableReason.CHANNEL_MISSING_IN_TEMPLATE.value
        status = resolution.status if resolution else self.senders.status(channel)
        if not status.configured:
            return False, SendableReason.CHANNEL_NOT_CONFIGURED.value
        own = resolution is not None and resolution.own
        synced = get("whatsapp_source") == "own_waba"
        order = list(get("whatsapp_variable_order") or [])
        if own and channel is Channel.SMS and get("organization_id") is None:
            # System templates carry Wyfy's DLT ids, registered to Wyfy's
            # entity and header; carriers drop them on the venue's header.
            return False, OWN_PROVIDER_REQUIRES_OWN_TEMPLATE
        if own and channel is Channel.WHATSAPP and not synced:
            return False, OWN_PROVIDER_REQUIRES_OWN_TEMPLATE
        if channel is Channel.SMS and not get("sms_dlt_template_id"):
            return False, SendableReason.DLT_TEMPLATE_ID_MISSING.value
        if channel is Channel.WHATSAPP and synced:
            if not own:
                # A template approved in the venue's WABA cannot be sent from
                # Wyfy's number.
                return False, SendableReason.WHATSAPP_NOT_APPROVED.value
            if get("whatsapp_approval_status") != WhatsAppApprovalStatus.APPROVED.value:
                return False, SendableReason.WHATSAPP_NOT_APPROVED.value
            if "unsubscribe_link" not in order or len(order) != placeholder_count(body):
                return False, SendableReason.UNSUBSCRIBE_LINK_MISSING.value
        elif channel is Channel.WHATSAPP and (
            not get("whatsapp_content_sid")
            or get("whatsapp_approval_status") != WhatsAppApprovalStatus.APPROVED.value
        ):
            return False, SendableReason.WHATSAPP_NOT_APPROVED.value
        if (
            channel in (Channel.SMS, Channel.EMAIL)
            and "{{unsubscribe_link}}" not in body
        ):
            return False, SendableReason.UNSUBSCRIBE_LINK_MISSING.value
        texts = [body]
        if channel is Channel.EMAIL:
            texts += [get("email_subject") or "", get("email_preheader") or ""]
        uses_review = any("{{review_link}}" in text for text in texts) or (
            synced and "review_link" in order
        )
        if uses_review and not review_url:
            return False, "review_link_missing"
        return True, None

    def template_resource(
        self,
        template: MarketingTemplate,
        *,
        review_url: str | None,
        resolutions: dict[Channel, ProviderResolution] | None = None,
    ) -> dict[str, Any]:
        variables: list[str] = []
        for text in (
            template.sms_body,
            template.whatsapp_body,
            template.email_subject,
            template.email_preheader,
            template.email_body_html,
        ):
            try:
                for name in extract_variables(text):
                    if name not in variables:
                        variables.append(name)
            except TemplateVariableError:
                continue
        sms = None
        if template.sms_body is not None:
            stats = sms_stats(template.sms_body)
            sms = {
                "body": template.sms_body,
                "dlt_template_id": template.sms_dlt_template_id,
                "length": stats.length,
                "encoding": stats.encoding,
                "segments": stats.segments,
            }
        whatsapp = None
        if template.whatsapp_body is not None:
            whatsapp = {
                "body": template.whatsapp_body,
                "content_sid": template.whatsapp_content_sid,
                "variable_order": template.whatsapp_variable_order or [],
                "approval_status": template.whatsapp_approval_status,
                # BYO (spec §12.4): "wyfy" for Wyfy-approved rows,
                # "own_waba" for templates synced from the venue's WABA.
                "source": getattr(template, "whatsapp_source", None) or "wyfy",
                "provider_template_name": getattr(
                    template, "whatsapp_provider_template_name", None
                ),
                "provider_language": getattr(
                    template, "whatsapp_provider_language", None
                ),
                "placeholder_count": placeholder_count(template.whatsapp_body)
                if getattr(template, "whatsapp_source", None) == "own_waba"
                else None,
            }
        email = None
        if template.email_body_html is not None:
            email = {
                "subject": template.email_subject,
                "preheader": template.email_preheader,
                "body_html": template.email_body_html,
            }
        sendable = {}
        for channel in CHANNEL_ORDER:
            ok, reason = self._sendable_for(
                template,
                channel,
                review_url=review_url,
                resolution=(resolutions or {}).get(channel),
            )
            sendable[channel.value] = {"ok": ok, "reason": reason}
        return {
            "id": str(template.id),
            "is_system": template.organization_id is None,
            "system_key": template.system_key,
            "name": template.name,
            "category": template.category,
            "description": template.description,
            "sms": sms,
            "whatsapp": whatsapp,
            "email": email,
            "variables": variables,
            "sendable": sendable,
            "version": template.version,
            "created_at": utc_iso(template.created_at),
            "updated_at": utc_iso(template.updated_at),
        }

    async def list_templates(
        self,
        scope: CallerScope,
        *,
        channel: Channel | None,
        category: TemplateCategory | None,
        include_system: bool,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        rows, meta = await self.repository.list_templates(
            organization_id=scope.organization_id,
            channel=channel.value if channel else None,
            category=category.value if category else None,
            include_system=include_system,
            page=page,
            page_size=page_size,
        )
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return [
            self.template_resource(row, review_url=review_url, resolutions=resolutions)
            for row in rows
        ], meta

    async def _get_template(
        self, scope: CallerScope, template_id: uuid.UUID
    ) -> MarketingTemplate:
        template = await self.repository.get_template(
            scope.organization_id, template_id
        )
        if template is None:
            raise TemplateNotFoundError("Template not found")
        return template

    async def get_template(
        self, scope: CallerScope, template_id: uuid.UUID
    ) -> dict[str, Any]:
        template = await self._get_template(scope, template_id)
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return self.template_resource(
            template, review_url=review_url, resolutions=resolutions
        )

    @staticmethod
    def _validate_variables(*texts: str | None) -> None:
        unknown: list[str] = []
        for text in texts:
            try:
                extract_variables(text)
            except TemplateVariableError as exc:
                unknown.extend(exc.variables)
        if unknown:
            raise UnknownVariableError(
                "Unknown or malformed template variables",
                variables=sorted(set(unknown)),
            )

    def _content_fields(self, sms, email) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if sms is not None:
            self._validate_variables(sms.body)
            problem = sms_body_problems(
                sms.body, unsubscribe_link_length=self.sms_unsubscribe_link_budget()
            )
            if problem == "unsubscribe_link_missing":
                raise UnsubscribeLinkMissingError(
                    "SMS body must contain {{unsubscribe_link}}"
                )
            if problem == "sms_too_long":
                raise SmsTooLongError("SMS is longer than 3 segments in the worst case")
            fields["sms_body"] = sms.body
            fields["sms_dlt_template_id"] = sms.dlt_template_id
        if email is not None:
            body = clean_email_html(email.body_html)
            if len(body.encode("utf-8")) > EMAIL_MAX_BODY_BYTES:
                raise MarketingValidationError("Email body is larger than 100 KB")
            self._validate_variables(email.subject, email.preheader, body)
            if "{{unsubscribe_link}}" not in body:
                raise UnsubscribeLinkMissingError(
                    "Email body must contain {{unsubscribe_link}}"
                )
            fields["email_subject"] = email.subject
            fields["email_preheader"] = email.preheader
            fields["email_body_html"] = body
        return fields

    async def create_template(
        self, scope: CallerScope, body: TemplateCreate
    ) -> dict[str, Any]:
        if body.whatsapp is not None:
            raise WhatsAppCustomNotSupportedError(
                "Custom WhatsApp templates are not supported yet"
            )
        if body.sms is None and body.email is None:
            raise TemplateEmptyError("A template needs at least one channel")
        fields = self._content_fields(body.sms, body.email)
        if await self.repository.template_name_taken(scope.organization_id, body.name):
            raise TemplateNameTakenError("A template with this name already exists")
        template = await self.repository.create_template(
            organization_id=scope.organization_id,
            system_key=None,
            name=body.name.strip(),
            category=body.category.value,
            description=body.description,
            whatsapp_approval_status=WhatsAppApprovalStatus.NOT_SUBMITTED.value,
            created_by=scope.actor_user_id,
            **fields,
        )
        await self._audit(
            scope,
            AuditAction.MARKETING_TEMPLATE_CREATED,
            entity_type="marketing_template",
            entity_id=template.id,
            organization_id=scope.organization_id,
            description=f"Marketing template '{template.name}' created",
        )
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return self.template_resource(
            template, review_url=review_url, resolutions=resolutions
        )

    async def _require_custom(
        self, scope: CallerScope, template_id: uuid.UUID
    ) -> MarketingTemplate:
        template = await self._get_template(scope, template_id)
        if template.organization_id is None:
            raise SystemTemplateReadOnlyError(
                "System templates are read-only; duplicate it instead"
            )
        return template

    async def update_template(
        self, scope: CallerScope, template_id: uuid.UUID, body: TemplateUpdate
    ) -> dict[str, Any]:
        template = await self._require_custom(scope, template_id)
        if getattr(template, "whatsapp_source", None) == "own_waba":
            return await self._update_synced_template(scope, template, body)
        if body.whatsapp is not None:
            raise WhatsAppCustomNotSupportedError(
                "Custom WhatsApp templates are not supported yet"
            )
        if template.version != body.version:
            raise VersionConflictError(
                "This template was changed by someone else",
                current_version=template.version,
            )
        if await self.repository.template_in_use(template.id):
            raise TemplateInUseError(
                "A scheduled or sending campaign uses this template; "
                "duplicate it instead"
            )
        data: dict[str, Any] = {}
        provided = body.model_fields_set
        if "name" in provided and body.name is not None:
            if await self.repository.template_name_taken(
                scope.organization_id, body.name, exclude_id=template.id
            ):
                raise TemplateNameTakenError("A template with this name already exists")
            data["name"] = body.name.strip()
        if "category" in provided and body.category is not None:
            data["category"] = body.category.value
        if "description" in provided:
            data["description"] = body.description
        data.update(
            self._content_fields(
                body.sms if "sms" in provided else None,
                body.email if "email" in provided else None,
            )
        )
        if "sms" in provided and body.sms is None:
            data["sms_body"] = None
            data["sms_dlt_template_id"] = None
        if "email" in provided and body.email is None:
            data["email_subject"] = None
            data["email_preheader"] = None
            data["email_body_html"] = None
        remaining_sms = data.get("sms_body", template.sms_body)
        remaining_email = data.get("email_body_html", template.email_body_html)
        if not remaining_sms and not remaining_email:
            raise TemplateEmptyError("A template needs at least one channel")
        data["updated_by"] = scope.actor_user_id
        if not await self.repository.update_template_cas(
            template, expected_version=body.version, data=data
        ):
            await self.repository.refresh(template)
            raise VersionConflictError(
                "This template was changed by someone else",
                current_version=template.version,
            )
        await self._audit(
            scope,
            AuditAction.MARKETING_TEMPLATE_UPDATED,
            entity_type="marketing_template",
            entity_id=template.id,
            organization_id=scope.organization_id,
            description=f"Marketing template '{template.name}' updated",
        )
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return self.template_resource(
            template, review_url=review_url, resolutions=resolutions
        )

    async def _update_synced_template(
        self, scope: CallerScope, template: MarketingTemplate, body: TemplateUpdate
    ) -> dict[str, Any]:
        """A template synced from the venue's WABA: its content is Meta's, so
        only ``name`` and ``whatsapp.variable_order`` may change (spec §12.4)."""
        provided = body.model_fields_set - {"version"}
        whatsapp = body.whatsapp if "whatsapp" in provided else None
        if provided - {"name", "whatsapp"} or (
            whatsapp is not None and set(whatsapp) - {"variable_order"}
        ):
            raise SyncedTemplateReadOnlyError(
                "Only the name and the variable mapping of a synced template "
                "can be changed"
            )
        if template.version != body.version:
            raise VersionConflictError(
                "This template was changed by someone else",
                current_version=template.version,
            )
        data: dict[str, Any] = {"updated_by": scope.actor_user_id}
        if "name" in provided and body.name:
            if await self.repository.template_name_taken(
                scope.organization_id, body.name, exclude_id=template.id
            ):
                raise TemplateNameTakenError("A template with this name already exists")
            data["name"] = body.name.strip()
        if whatsapp is not None:
            order = whatsapp.get("variable_order")
            if not isinstance(order, list) or not all(
                isinstance(item, str) for item in order
            ):
                raise MarketingValidationError("variable_order must be a list of names")
            if len(order) != placeholder_count(template.whatsapp_body):
                raise MarketingValidationError(
                    "variable_order must map every {{n}} placeholder",
                    placeholder_count=placeholder_count(template.whatsapp_body),
                )
            unknown = sorted(set(order) - TEMPLATE_VARIABLES)
            if unknown:
                raise UnknownVariableError("Unknown variables", variables=unknown)
            data["whatsapp_variable_order"] = order
        if not await self.repository.update_template_cas(
            template, expected_version=body.version, data=data
        ):
            await self.repository.refresh(template)
            raise VersionConflictError(
                "This template was changed by someone else",
                current_version=template.version,
            )
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return self.template_resource(
            template, review_url=review_url, resolutions=resolutions
        )

    async def delete_template(
        self, scope: CallerScope, template_id: uuid.UUID
    ) -> dict[str, Any]:
        template = await self._require_custom(scope, template_id)
        if await self.repository.template_in_use(template.id):
            raise TemplateInUseError(
                "A scheduled or sending campaign uses this template"
            )
        await self.repository.soft_delete_template(template)
        await self._audit(
            scope,
            AuditAction.MARKETING_TEMPLATE_DELETED,
            entity_type="marketing_template",
            entity_id=template.id,
            organization_id=scope.organization_id,
            description=f"Marketing template '{template.name}' deleted",
        )
        return {"id": str(template.id), "deleted": True}

    async def duplicate_template(
        self, scope: CallerScope, template_id: uuid.UUID, name: str
    ) -> dict[str, Any]:
        source = await self._get_template(scope, template_id)
        if await self.repository.template_name_taken(scope.organization_id, name):
            raise TemplateNameTakenError("A template with this name already exists")
        if not source.sms_body and not source.email_body_html:
            raise TemplateEmptyError(
                "This template has only WhatsApp content, which cannot be copied yet"
            )
        template = await self.repository.create_template(
            organization_id=scope.organization_id,
            system_key=None,
            name=name.strip(),
            category=source.category,
            description=source.description,
            sms_body=source.sms_body,
            # A DLT registration belongs to the exact registered text; a copy
            # is a new template as far as the carrier is concerned.
            sms_dlt_template_id=None,
            email_subject=source.email_subject,
            email_preheader=source.email_preheader,
            email_body_html=source.email_body_html,
            whatsapp_approval_status=WhatsAppApprovalStatus.NOT_SUBMITTED.value,
            created_by=scope.actor_user_id,
        )
        await self._audit(
            scope,
            AuditAction.MARKETING_TEMPLATE_CREATED,
            entity_type="marketing_template",
            entity_id=template.id,
            organization_id=scope.organization_id,
            description=(
                f"Marketing template '{template.name}' duplicated from "
                f"'{source.name}'"
            ),
        )
        review_url = await self._review_url(scope.organization_id, scope.location_id)
        resolutions = await self.resolve_providers(scope.organization_id)
        return self.template_resource(
            template, review_url=review_url, resolutions=resolutions
        )

    async def preview_template(
        self, scope: CallerScope, body: TemplatePreviewRequest
    ) -> dict[str, Any]:
        location_id = await self.resolve_single_location(scope, body.location_id)
        organization = await self._organization(scope.organization_id)
        channel = body.channel
        if body.template_id is not None:
            template = await self._get_template(scope, body.template_id)
            texts = {
                Channel.SMS: (template.sms_body, None),
                Channel.WHATSAPP: (template.whatsapp_body, None),
                Channel.EMAIL: (template.email_body_html, template.email_subject),
            }[channel]
        else:
            content = body.content
            assert content is not None
            if channel is Channel.SMS and content.sms is not None:
                texts = (content.sms.body, None)
            elif channel is Channel.EMAIL and content.email is not None:
                texts = (
                    clean_email_html(content.email.body_html),
                    content.email.subject,
                )
            else:
                raise ChannelMissingInTemplateError("No content for this channel")
        body_text, subject = texts
        if body_text is None:
            raise ChannelMissingInTemplateError(
                "The template has no content for this channel"
            )
        self._validate_variables(body_text, subject)
        unknown = sorted(set(body.variables) - set(CAMPAIGN_VARIABLE_MAX_LENGTHS))
        if unknown:
            raise UnknownVariableError("Unknown campaign variables", variables=unknown)
        location_name = organization.name
        if location_id is not None:
            location = await self._require_location(scope, location_id)
            location_name = location.name
        values = {
            "guest_name": SAMPLE_GUEST_NAME,
            "venue_name": organization.name,
            "location_name": location_name,
            "unsubscribe_link": self._unsubscribe_link(SAMPLE_UNSUBSCRIBE_TOKEN),
            **{key: value for key, value in body.variables.items() if value},
        }
        review_url = await self._review_url(scope.organization_id, location_id)
        if review_url:
            values["review_link"] = review_url
        values = bound_values(values)
        referenced = extract_variables(body_text) + extract_variables(subject)
        missing = sorted({name for name in referenced if not values.get(name)})
        rendered_body = render(body_text, values, escape_html=channel is Channel.EMAIL)
        rendered_subject = render(subject, values) if subject is not None else None
        sms = None
        if channel is Channel.SMS:
            stats = sms_stats(rendered_body)
            sms = {
                "length": stats.length,
                "encoding": stats.encoding,
                "segments": stats.segments,
            }
        return {
            "channel": channel.value,
            "rendered": {"body": rendered_body, "subject": rendered_subject},
            "sms": sms,
            "missing_variables": missing,
        }

    # ======================================================================
    # Campaigns (§5.5)
    # ======================================================================

    async def campaign_resources(
        self, campaigns: list[MarketingCampaign]
    ) -> list[dict[str, Any]]:
        templates = await self.repository.template_names(
            [c.template_id for c in campaigns]
        )
        users = await self.repository.get_user_names(
            [c.created_by_user_id for c in campaigns if c.created_by_user_id]
        )
        rows: dict[uuid.UUID, Any] = {}
        for campaign in campaigns:
            provider_id = getattr(campaign, "org_provider_id", None)
            if provider_id is not None and provider_id not in rows:
                rows[provider_id] = await self.repository.get_provider_by_id(
                    campaign.organization_id, provider_id
                )
        totals: dict[uuid.UUID, tuple[int, int, int]] = {}
        if self.credits is not None and campaigns:
            by_org: dict[uuid.UUID, list[uuid.UUID]] = {}
            for c in campaigns:
                by_org.setdefault(c.organization_id, []).append(c.id)
            for org_id, ids in by_org.items():
                totals.update(await self.credits.totals(org_id, ids))
        return [
            {
                **self._campaign_resource(c, templates, users),
                "provider": _campaign_provider(c, rows),
                "credits": _campaign_credits(c, totals.get(c.id)),
            }
            for c in campaigns
        ]

    def _campaign_resource(
        self,
        campaign: MarketingCampaign,
        templates: dict[uuid.UUID, MarketingTemplate],
        users: dict[uuid.UUID, str],
    ) -> dict[str, Any]:
        template = templates.get(campaign.template_id)
        return {
            "id": str(campaign.id),
            "name": campaign.name,
            "channel": campaign.channel,
            "location_id": str(campaign.location_id) if campaign.location_id else None,
            "template": {
                "id": str(campaign.template_id),
                "name": template.name if template else None,
                "is_system": template.organization_id is None if template else False,
            },
            "variables": campaign.variables or {},
            "audience_filter": campaign.audience_filter,
            "status": campaign.status,
            "scheduled_at": utc_iso(campaign.scheduled_at),
            "started_at": utc_iso(campaign.started_at),
            "completed_at": utc_iso(campaign.completed_at),
            "cancelled_at": utc_iso(campaign.cancelled_at),
            "cancel_reason": campaign.cancel_reason,
            "paused_until": utc_iso(campaign.paused_until),
            "stats": {
                "recipients": campaign.recipient_count,
                "pending": campaign.count_pending,
                "submitted": campaign.count_submitted,
                "delivered": campaign.count_delivered,
                "failed": campaign.count_failed,
                "skipped": campaign.count_skipped,
                # No provider in MVP reports delivery receipts.
                "delivered_is_tracked": False,
                "excluded_at_dispatch": campaign.exclusion_counts,
                "capped_by_credits": getattr(campaign, "capped_by_credits", 0) or 0,
            },
            "created_by": {
                "id": str(campaign.created_by_user_id),
                "name": users.get(campaign.created_by_user_id),
            }
            if campaign.created_by_user_id
            else None,
            "version": campaign.version,
            "created_at": utc_iso(campaign.created_at),
            "updated_at": utc_iso(campaign.updated_at),
        }

    async def campaign_detail(self, campaign: MarketingCampaign) -> dict[str, Any]:
        (resource,) = await self.campaign_resources([campaign])
        resource["last_error"] = campaign.last_error
        return resource

    async def _get_campaign(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> MarketingCampaign:
        self._guard(scope)
        campaign = await self.repository.get_campaign(
            scope.organization_id, campaign_id, scope_location_id=scope.location_id
        )
        if campaign is None:
            raise MarketingNotFoundError("Campaign not found")
        return campaign

    async def _venue_filter(
        self, scope: CallerScope, location_id: uuid.UUID | None
    ) -> uuid.UUID | None:
        """The ``location_id`` list filter (contract change 2026-09-25) under
        LocScope: a location-scoped caller's omitted filter means their own
        venue -- never "unfiltered" -- and any other venue is 403
        ``cross_location``. An org-scoped caller's filter must be one of the
        org's venues (404 ``location_not_found``); omitted = no filter."""
        if scope.location_id is not None:
            if location_id is not None and location_id != scope.location_id:
                raise CrossLocationError("You can only view your own location.")
            return scope.location_id
        if location_id is not None:
            await self._require_location(scope, location_id)
        return location_id

    async def list_campaigns(
        self,
        scope: CallerScope,
        *,
        statuses: list[str] | None,
        channel: Channel | None,
        search: str | None,
        page: int,
        page_size: int,
        location_id: uuid.UUID | None = None,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        self._guard(scope)
        venue = await self._venue_filter(scope, location_id)
        rows, meta = await self.repository.list_campaigns(
            organization_id=scope.organization_id,
            scope_location_id=scope.location_id,
            statuses=statuses,
            channel=channel.value if channel else None,
            search=search,
            page=page,
            page_size=page_size,
            venue_location_id=venue,
        )
        return await self.campaign_resources(rows), meta

    async def get_campaign(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> dict[str, Any]:
        return await self.campaign_detail(await self._get_campaign(scope, campaign_id))

    async def _check_campaign_content(
        self,
        scope: CallerScope,
        *,
        channel: Channel,
        template_id: uuid.UUID,
        audience: AudienceFilter,
        variables: dict[str, str],
    ) -> MarketingTemplate:
        if audience.channel is not channel:
            raise ChannelMismatchError("audience_filter.channel must equal channel")
        template = await self._get_template(scope, template_id)
        if not self._template_body(template, channel):
            raise ChannelMissingInTemplateError(
                "The template has no content for this channel"
            )
        unknown = sorted(set(variables) - set(CAMPAIGN_VARIABLE_MAX_LENGTHS))
        if unknown:
            raise UnknownVariableError("Unknown campaign variables", variables=unknown)
        return template

    @staticmethod
    def _template_body(template: MarketingTemplate, channel: Channel) -> str | None:
        return {
            Channel.SMS: template.sms_body,
            Channel.WHATSAPP: template.whatsapp_body,
            Channel.EMAIL: template.email_body_html,
        }[channel]

    async def create_campaign(
        self, scope: CallerScope, body: CampaignCreate
    ) -> dict[str, Any]:
        location_id = await self.resolve_single_location(scope, body.location_id)
        await self._check_campaign_content(
            scope,
            channel=body.channel,
            template_id=body.template_id,
            audience=body.audience_filter,
            variables=body.variables,
        )
        # Validate (and, for a location-scoped caller, rewrite) the audience
        # locations now, so a stored filter never names a foreign location.
        audience = body.audience_filter.model_copy(
            update={
                "location_ids": await self.resolve_location_ids(
                    scope, body.audience_filter.location_ids
                )
            }
        )
        campaign = await self.repository.create_campaign(
            organization_id=scope.organization_id,
            location_id=location_id,
            name=body.name.strip(),
            channel=body.channel.value,
            template_id=body.template_id,
            variables=body.variables,
            audience_filter=audience.model_dump(mode="json"),
            status=CampaignStatus.DRAFT.value,
            created_by_user_id=scope.actor_user_id,
            created_by=scope.actor_user_id,
        )
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_CREATED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            location_id=location_id,
            description=f"Marketing campaign '{campaign.name}' created",
        )
        return await self.campaign_detail(campaign)

    async def update_campaign(
        self, scope: CallerScope, campaign_id: uuid.UUID, body: CampaignUpdate
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        if campaign.status != CampaignStatus.DRAFT.value:
            raise InvalidStatusTransitionError("Only a draft can be edited")
        if campaign.version != body.version:
            raise VersionConflictError(
                "This campaign was changed by someone else",
                current_version=campaign.version,
            )
        provided = body.model_fields_set
        channel = (
            body.channel
            if "channel" in provided and body.channel
            else Channel(campaign.channel)
        )
        template_id = (
            body.template_id
            if "template_id" in provided and body.template_id
            else campaign.template_id
        )
        variables = (
            body.variables
            if "variables" in provided and body.variables is not None
            else (campaign.variables or {})
        )
        audience = (
            body.audience_filter
            if "audience_filter" in provided and body.audience_filter is not None
            else AudienceFilter.model_validate(campaign.audience_filter)
        )
        await self._check_campaign_content(
            scope,
            channel=channel,
            template_id=template_id,
            audience=audience,
            variables=variables,
        )
        audience = audience.model_copy(
            update={
                "location_ids": await self.resolve_location_ids(
                    scope, audience.location_ids
                )
            }
        )
        data: dict[str, Any] = {
            "channel": channel.value,
            "template_id": template_id,
            "variables": variables,
            "audience_filter": audience.model_dump(mode="json"),
            "updated_by": scope.actor_user_id,
        }
        if "name" in provided and body.name:
            data["name"] = body.name.strip()
        if "location_id" in provided:
            data["location_id"] = await self.resolve_single_location(
                scope, body.location_id
            )
        if not await self.repository.update_campaign_cas(
            campaign,
            expected_status=CampaignStatus.DRAFT.value,
            expected_version=body.version,
            data=data,
        ):
            await self.repository.refresh(campaign)
            if campaign.status != CampaignStatus.DRAFT.value:
                raise InvalidStatusTransitionError("Only a draft can be edited")
            raise VersionConflictError(
                "This campaign was changed by someone else",
                current_version=campaign.version,
            )
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_UPDATED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=f"Marketing campaign '{campaign.name}' updated",
        )
        return await self.campaign_detail(campaign)

    async def delete_campaign(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        if campaign.status not in (
            CampaignStatus.DRAFT.value,
            CampaignStatus.CANCELLED.value,
        ):
            raise InvalidStatusTransitionError(
                "Only a draft or cancelled campaign can be deleted"
            )
        await self.repository.soft_delete_campaign(campaign)
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_DELETED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=f"Marketing campaign '{campaign.name}' deleted",
        )
        return {"id": str(campaign.id), "deleted": True}

    # -- rendering ---------------------------------------------------------

    def _unsubscribe_link(self, token: str) -> str:
        base = (
            self.settings.marketing_unsubscribe_base_url
            or self.settings.frontend_base_url
        ).rstrip("/")
        return f"{base}/u/{token}"

    async def _build_snapshot(
        self, campaign: MarketingCampaign, template: MarketingTemplate
    ) -> dict[str, Any]:
        organization = await self._organization(campaign.organization_id)
        location = (
            await self.repository.get_location(
                campaign.organization_id, campaign.location_id
            )
            if campaign.location_id
            else None
        )
        review_url = await self._review_url(
            campaign.organization_id, campaign.location_id
        )
        address = None
        if location is not None:
            address = ", ".join(
                part
                for part in (
                    location.address_line1,
                    getattr(location, "address_line2", None),
                    location.city,
                    location.state_province,
                )
                if part
            )
        return {
            "channel": campaign.channel,
            "template_id": str(template.id),
            "template_version": template.version,
            "sms_body": template.sms_body,
            "sms_dlt_template_id": template.sms_dlt_template_id,
            "whatsapp_body": template.whatsapp_body,
            "whatsapp_content_sid": template.whatsapp_content_sid,
            "whatsapp_variable_order": template.whatsapp_variable_order or [],
            "whatsapp_approval_status": template.whatsapp_approval_status,
            "whatsapp_source": getattr(template, "whatsapp_source", None),
            "whatsapp_provider_template_name": getattr(
                template, "whatsapp_provider_template_name", None
            ),
            "whatsapp_provider_language": getattr(
                template, "whatsapp_provider_language", None
            ),
            # Template owner (None = system template) -- the own-provider
            # sendability rule for SMS needs it.
            "organization_id": str(template.organization_id)
            if template.organization_id
            else None,
            "email_subject": template.email_subject,
            "email_preheader": template.email_preheader,
            "email_body_html": template.email_body_html,
            "venue_name": organization.name,
            "location_name": location.name if location else organization.name,
            "venue_address": address,
            "reply_to": organization.contact_email,
            "review_link": review_url,
        }

    def _values(
        self,
        snapshot: dict[str, Any],
        variables: dict[str, Any],
        *,
        guest_name: str | None,
        token: str,
    ) -> dict[str, str]:
        values: dict[str, str] = {
            "guest_name": (guest_name or "").strip() or GUEST_NAME_FALLBACK,
            "venue_name": snapshot.get("venue_name") or "",
            "location_name": snapshot.get("location_name") or "",
            "unsubscribe_link": self._unsubscribe_link(token),
        }
        if snapshot.get("review_link"):
            values["review_link"] = snapshot["review_link"]
        for key in CAMPAIGN_VARIABLE_MAX_LENGTHS:
            if variables.get(key):
                values[key] = str(variables[key])
        return bound_values(values)

    @staticmethod
    def _email_layout(
        snapshot: dict[str, Any], body_html: str, preheader: str, unsubscribe: str
    ) -> str:
        venue = html.escape(snapshot.get("venue_name") or "")
        address = html.escape(snapshot.get("venue_address") or "")
        footer_address = f"<br>{address}" if address else ""
        return _EMAIL_LAYOUT.format(
            preheader=html.escape(preheader),
            venue=venue,
            body=body_html,
            footer_address=footer_address,
            link=html.escape(unsubscribe, quote=True),
        )

    async def _deliver(
        self,
        channel: Channel,
        snapshot: dict[str, Any],
        values: dict[str, str],
        address: str,
        *,
        test: bool = False,
        own: OwnSenders | None = None,
    ) -> tuple[ProviderResult, str]:
        """Render and hand one message to the channel's sender -- the
        venue's own adapter when ``own`` is given (the campaign snapshot said
        so), Wyfy's otherwise. Never both, never a fallback. Returns the
        provider result and a ≤200-char rendered preview. Raises
        ``SendError`` on any provider failure."""
        if channel is Channel.SMS:
            sender = own.sms if own is not None else self.senders.sms
            if sender is None:
                raise SendError(
                    "channel_not_configured",
                    "SMS sender not configured",
                    permanent=True,
                )
            body = render(snapshot.get("sms_body"), values)
            if test:
                body = f"[TEST] {body}"
            result = await sender.send(
                address, body, dlt_template_id=snapshot.get("sms_dlt_template_id") or ""
            )
            return result, body[:200]
        if channel is Channel.WHATSAPP and own is not None:
            if own.whatsapp is None:
                raise SendError(
                    "channel_not_configured",
                    "Own WhatsApp not configured",
                    permanent=True,
                )
            order = snapshot.get("whatsapp_variable_order") or []
            parameters = [values.get(name, "") for name in order]
            result = await own.whatsapp.send_waba_template(
                address,
                template_name=snapshot.get("whatsapp_provider_template_name") or "",
                language=snapshot.get("whatsapp_provider_language") or "en",
                parameters=parameters,
            )
            return result, render_positional(snapshot.get("whatsapp_body"), parameters)[
                :200
            ]
        if channel is Channel.WHATSAPP:
            sender = self.senders.whatsapp
            if sender is None:
                raise SendError(
                    "channel_not_configured",
                    "WhatsApp sender not configured",
                    permanent=True,
                )
            order = snapshot.get("whatsapp_variable_order") or []
            variables = {
                str(index + 1): values.get(name, "") for index, name in enumerate(order)
            }
            result = await sender.send_template(
                address,
                content_sid=snapshot.get("whatsapp_content_sid") or "",
                variables=variables,
            )
            return result, render(snapshot.get("whatsapp_body"), values)[:200]
        sender = own.email if own is not None else self.senders.email
        if sender is None:
            raise SendError(
                "channel_not_configured", "Email sender not configured", permanent=True
            )
        subject = render(snapshot.get("email_subject"), values)
        if test:
            subject = f"[TEST] {subject}"
        preheader = render(snapshot.get("email_preheader"), values)
        inner = render(snapshot.get("email_body_html"), values, escape_html=True)
        unsubscribe = values["unsubscribe_link"]
        document = self._email_layout(snapshot, inner, preheader, unsubscribe)
        list_unsubscribe = f"<{unsubscribe}>"
        mailto = self.settings.marketing_email_unsubscribe_mailto
        if mailto:
            token = unsubscribe.rsplit("/", 1)[-1]
            list_unsubscribe += f", <mailto:{mailto}?subject={token}>"
        headers = {
            "List-Unsubscribe": list_unsubscribe,
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        }
        if snapshot.get("reply_to"):
            headers["Reply-To"] = snapshot["reply_to"]
        result = await sender.send(
            address,
            subject=subject,
            html_body=document,
            # Own account: the venue's own name (its own from_name config
            # wins inside the adapter). Wyfy's shared domain says "via".
            from_name=(snapshot.get("venue_name") or "Wyfy Guest")
            if own is not None
            else f"{snapshot.get('venue_name') or 'Wyfy Guest'} via Wyfy Guest",
            headers=headers,
        )
        return result, f"{subject} | {render(snapshot.get('email_body_html'), values)}"[
            :200
        ]

    # -- readiness ---------------------------------------------------------

    def _require_channel_configured(
        self, channel: Channel, resolution: ProviderResolution | None = None
    ) -> None:
        status = resolution.status if resolution else self.senders.status(channel)
        if not status.configured:
            raise ChannelNotConfiguredError(
                status.reason or "This channel is not configured",
                channel_status=status.as_dict(),
            )

    def _require_sendable(
        self,
        snapshot_or_template,
        channel: Channel,
        review_url: str | None,
        resolution: ProviderResolution | None = None,
    ) -> None:
        ok, reason = self._sendable_for(
            snapshot_or_template,
            channel,
            review_url=review_url,
            resolution=resolution,
        )
        if not ok:
            if reason == SendableReason.CHANNEL_NOT_CONFIGURED.value:
                self._require_channel_configured(channel, resolution)
            raise TemplateNotSendableError(
                "This template cannot be sent on this channel yet", reason=reason
            )

    async def _snapshot_row(
        self, campaign: MarketingCampaign
    ) -> tuple[Any | None, str]:
        """The own-provider row a campaign was snapshotted to, if it is still
        usable. Returns (row, "") or (None, reason) -- never a fallback."""
        provider_id = getattr(campaign, "org_provider_id", None)
        if provider_id is None:
            return None, "provider removed"
        row = await self.repository.get_provider_by_id(
            campaign.organization_id, provider_id
        )
        if row is None or row.is_deleted:
            return None, "provider removed"
        if row.status == "failed":
            return None, f"provider failed: {row.last_error or 'verification failed'}"
        if row.status != "verified":
            return None, "provider not verified"
        if not row.enabled:
            return None, "provider disabled"
        return row, ""

    async def test_send(
        self,
        scope: CallerScope,
        campaign_id: uuid.UUID,
        to: list[str],
        sample_guest_name: str | None,
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        if campaign.status == CampaignStatus.CANCELLED.value:
            raise InvalidStatusTransitionError(
                "A cancelled campaign cannot be test-sent"
            )
        channel = Channel(campaign.channel)
        # A draft tests through whatever §12.1 resolves to now; a scheduled
        # or sent campaign tests through its own snapshot.
        resolution = (await self.resolve_providers(scope.organization_id))[channel]
        own: OwnSenders | None = None
        if campaign.status != CampaignStatus.DRAFT.value:
            if getattr(campaign, "provider_source", "wyfy") == "own":
                row, reason = await self._snapshot_row(campaign)
                if row is None:
                    raise ChannelNotConfiguredError(
                        f"own_provider_unavailable: {reason}",
                        channel_status=resolution.as_status_dict(),
                    )
                own = self.own_sender_factory(row)
                resolution = ProviderResolution(
                    channel, "own", row, _own_status(channel, row), True
                )
            else:
                resolution = ProviderResolution(
                    channel, "wyfy", None, self.senders.status(channel), False
                )
        elif resolution.own:
            own = self.own_sender_factory(resolution.row)
        self._require_channel_configured(channel, resolution)
        addresses = []
        for raw in to:
            normalized = normalize_address(channel, raw)
            if normalized is None:
                raise InvalidAddressError(
                    "Every test address must be valid for the channel",
                    address=mask_address(channel, raw),
                )
            addresses.append(normalized)
        template = await self._get_template(scope, campaign.template_id)
        snapshot = campaign.template_snapshot or await self._build_snapshot(
            campaign, template
        )
        self._require_sendable(
            snapshot, channel, snapshot.get("review_link"), resolution
        )
        # §13.4 step 7: a Wyfy-provider test send is charged per accepted
        # message from *available* (never reserved), at the campaign's
        # snapshot price once scheduled, the current price for a draft. An
        # own-provider test is free.
        test_price: dict[str, Any] | None = None
        if self.credits is not None and own is None:
            test_price = getattr(campaign, "price_snapshot", None)
            if campaign.status == CampaignStatus.DRAFT.value or not test_price:
                test_price = await self.credits.quote(
                    scope.organization_id,
                    channel,
                    snapshot,
                    unsubscribe_link_budget=self.sms_unsubscribe_link_budget(),
                )
            # The [TEST] prefix can add a segment; budget one extra.
            worst = per_recipient_minor(test_price) + (
                test_price["unit_price_minor"] if channel is Channel.SMS else 0
            )
            needed = worst * len(addresses)
            available = await self.credits.available_minor(scope.organization_id)
            if needed > available:
                from app.domains.billing.credits_exceptions import (
                    InsufficientCreditsError,
                )

                raise InsufficientCreditsError(
                    needed_minor=needed,
                    available_minor=available,
                    extra={
                        "unit_price_minor": test_price["unit_price_minor"],
                        "units_per_recipient_max": test_price[
                            "units_per_recipient_max"
                        ],
                        "reachable": len(addresses),
                    },
                )
        request_id = uuid.uuid4().hex
        await self._consume_test_quota(scope.organization_id, len(addresses))
        results = []
        for address in addresses:
            values = self._values(
                snapshot,
                campaign.variables or {},
                guest_name=sample_guest_name or SAMPLE_GUEST_NAME,
                token=SAMPLE_UNSUBSCRIBE_TOKEN,
            )
            try:
                result, _ = await self._deliver(
                    channel, snapshot, values, address, test=True, own=own
                )
                charged = 0
                if test_price is not None and self.credits is not None:
                    charged = await self.credits.charge_test_send(
                        campaign,
                        request_id=request_id,
                        address=address,
                        unit_price_minor=int(test_price["unit_price_minor"]),
                        units=actual_units(channel, snapshot, values, test=True),
                    )
                results.append(
                    {
                        "to_masked": mask_address(channel, address),
                        "status": RecipientStatus.SUBMITTED.value,
                        "provider_message_id": result.message_id,
                        "error_code": None,
                        "charged_minor": charged,
                    }
                )
            except SendError as exc:
                logger.warning(
                    "marketing_test_send_failed",
                    extra={"campaign_id": str(campaign.id), "error_code": exc.code},
                )
                results.append(
                    {
                        "to_masked": mask_address(channel, address),
                        "status": RecipientStatus.FAILED.value,
                        "provider_message_id": None,
                        "error_code": "provider_rejected",
                        "charged_minor": 0,
                    }
                )
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_TEST_SENT,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=(
                f"Test send of '{campaign.name}' to {len(addresses)} address(es)"
            ),
            metadata={
                "to": [mask_address(channel, address) for address in addresses],
                "statuses": [item["status"] for item in results],
            },
        )
        return {"results": results}

    async def _consume_test_quota(self, organization_id: uuid.UUID, count: int) -> None:
        limit = self.settings.marketing_test_sends_per_day
        if self.redis is None:
            return
        now = self._now()
        key = TEST_SEND_COUNTER_KEY_TEMPLATE.format(
            organization_id=organization_id, day=now.strftime("%Y%m%d")
        )
        used = await self.redis.incrby(key, count)
        if used == count:
            await self.redis.expire(key, 60 * 60 * 25)
        if used > limit:
            await self.redis.decrby(key, count)
            tomorrow = (now + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            raise DailyTestSendLimitError(
                "Daily test-send limit reached",
                retry_after_seconds=int((tomorrow - now).total_seconds()),
            )

    async def schedule(
        self,
        scope: CallerScope,
        campaign_id: uuid.UUID,
        *,
        scheduled_at: datetime | None,
        idempotency_key: str,
        acknowledge_wyfy_fallback: bool = False,
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        now = self._now()
        existing = await self.repository.find_campaign_by_idempotency_key(
            scope.organization_id, idempotency_key
        )
        if existing is not None:
            fresh = (
                existing.schedule_idempotency_at
                and existing.schedule_idempotency_at
                > now - timedelta(hours=SCHEDULE_IDEMPOTENCY_WINDOW_HOURS)
            )
            if existing.id == campaign.id and fresh:
                return await self.campaign_detail(campaign)
            raise MarketingValidationError(
                "idempotency_key was already used for another request"
            )
        if campaign.status != CampaignStatus.DRAFT.value:
            raise InvalidStatusTransitionError("Only a draft can be scheduled")
        channel = Channel(campaign.channel)
        resolution = (await self.resolve_providers(scope.organization_id))[channel]
        if resolution.needs_fallback_ack and not acknowledge_wyfy_fallback:
            # Founder Q11 = Option A: the org has its own provider for this
            # channel but it is not usable, so this would go through Wyfy --
            # only with an explicit acknowledgement, never silently.
            raise OwnProviderUnacknowledgedError(
                "Your own provider for this channel is not usable; this "
                "campaign would be sent through Wyfy's default account.",
                channel_status=resolution.as_status_dict(),
            )
        self._require_channel_configured(channel, resolution)
        template = await self._get_template(scope, campaign.template_id)
        snapshot = await self._build_snapshot(campaign, template)
        self._require_sendable(
            snapshot, channel, snapshot.get("review_link"), resolution
        )

        if scheduled_at is not None:
            if scheduled_at.tzinfo is None:
                scheduled_at = scheduled_at.replace(tzinfo=UTC)
            if scheduled_at < now + timedelta(minutes=SCHEDULE_MIN_LEAD_MINUTES) or (
                scheduled_at > now + timedelta(days=SCHEDULE_MAX_LEAD_DAYS)
            ):
                raise ScheduleOutOfRangeError(
                    "scheduled_at must be at least 5 minutes and at most 60 days ahead"
                )
        send_at = scheduled_at or now
        organization = await self._organization(scope.organization_id)
        zone = self._zone(organization)
        if channel in QUIET_HOURS_CHANNELS and in_quiet_hours(
            send_at,
            start=self.settings.marketing_quiet_hours_start,
            end=self.settings.marketing_quiet_hours_end,
            zone=zone,
        ):
            raise QuietHoursError(
                "Promotional messages cannot be sent during quiet hours",
                next_allowed_at=utc_iso(
                    next_allowed_at(
                        send_at,
                        start=self.settings.marketing_quiet_hours_start,
                        end=self.settings.marketing_quiet_hours_end,
                        zone=zone,
                    )
                ),
            )
        audience = AudienceFilter.model_validate(campaign.audience_filter)
        audience_scope = CallerScope(
            organization_id=scope.organization_id,
            location_id=scope.location_id,
            actor_user_id=scope.actor_user_id,
        )
        preview, _ = await self.evaluate_audience(audience_scope, audience)
        if preview["reachable"] == 0:
            raise AudienceEmptyError(
                "No guests can be reached with this audience", preview=preview
            )
        limit = self.settings.marketing_max_recipients_per_campaign
        if preview["reachable"] > limit:
            raise AudienceTooLargeError(
                "Too many recipients for one campaign",
                reachable=preview["reachable"],
                limit=limit,
            )
        target_status = (
            CampaignStatus.SCHEDULED.value
            if scheduled_at
            else CampaignStatus.SENDING.value
        )
        # §13.4 steps 1-2: Wyfy provider only -- freeze the price and reserve
        # for the whole reachable audience, or 402 while still a draft. An
        # own-provider campaign has no price, no reservation, no ledger row.
        price_snapshot: dict[str, Any] | None = None
        if self.credits is not None and not resolution.own:
            price_snapshot = await self.credits.quote(
                scope.organization_id,
                channel,
                snapshot,
                unsubscribe_link_budget=self.sms_unsubscribe_link_budget(),
            )
            await self.credits.reserve_at_schedule(
                campaign, price_snapshot, preview["reachable"]
            )
        data: dict[str, Any] = {
            "status": target_status,
            "scheduled_at": scheduled_at,
            "template_snapshot": snapshot,
            "schedule_idempotency_key": idempotency_key,
            "schedule_idempotency_at": now,
            "last_error": None,
            "updated_by": scope.actor_user_id,
            # §12.1 snapshot: the only thing dispatch and send_batch read.
            "provider_source": resolution.source,
            "provider_type": resolution.row.provider_type if resolution.own else None,
            "org_provider_id": resolution.row.id if resolution.own else None,
            "price_snapshot": price_snapshot,
            "capped_by_credits": 0,
        }
        if target_status == CampaignStatus.SENDING.value:
            data["started_at"] = now
        if not await self.repository.update_campaign_cas(
            campaign, expected_status=CampaignStatus.DRAFT.value, data=data
        ):
            raise InvalidStatusTransitionError("Only a draft can be scheduled")
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_SCHEDULED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=(
                f"Marketing campaign '{campaign.name}' "
                + (
                    f"scheduled for {utc_iso(scheduled_at)}"
                    if scheduled_at
                    else "sent now"
                )
            ),
            metadata={
                "reachable_at_schedule": preview["reachable"],
                "provider_source": resolution.source,
                "price_snapshot": price_snapshot,
                "acknowledged_wyfy_fallback": bool(
                    resolution.needs_fallback_ack and acknowledge_wyfy_fallback
                ),
            },
        )
        if target_status == CampaignStatus.SENDING.value:
            await self.materialize(campaign)
            await self.repository.commit()
            self._enqueue(campaign.id, 0)
            await self.repository.refresh(campaign)
        return await self.campaign_detail(campaign)

    def _enqueue(self, campaign_id: uuid.UUID, countdown: int) -> None:
        if self.enqueue_batch is not None:
            self.enqueue_batch(campaign_id, countdown)

    async def unschedule(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        if not await self.repository.update_campaign_cas(
            campaign,
            expected_status=CampaignStatus.SCHEDULED.value,
            data={
                "status": CampaignStatus.DRAFT.value,
                "scheduled_at": None,
                "template_snapshot": None,
                "provider_source": "wyfy",
                "provider_type": None,
                "org_provider_id": None,
                "schedule_idempotency_key": None,
                "schedule_idempotency_at": None,
                "price_snapshot": None,
                "capped_by_credits": 0,
                "updated_by": scope.actor_user_id,
            },
        ):
            raise InvalidStatusTransitionError(
                "Only a scheduled campaign can be unscheduled"
            )
        if self.credits is not None:
            # Back to draft: it holds nothing. A reschedule reserves afresh
            # (reserve:{id}:{n+1}) at the price of that day.
            await self.credits.release_all(
                campaign, key_base=f"release:{campaign.id}:unschedule"
            )
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_STATUS_CHANGED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=f"Marketing campaign '{campaign.name}' unscheduled",
        )
        return await self.campaign_detail(campaign)

    async def cancel(
        self, scope: CallerScope, campaign_id: uuid.UUID
    ) -> dict[str, Any]:
        campaign = await self._get_campaign(scope, campaign_id)
        now = self._now()
        if not await self.repository.update_campaign_cas(
            campaign,
            expected_status=[s.value for s in ACTIVE_CAMPAIGN_STATUSES],
            data={
                "status": CampaignStatus.CANCELLED.value,
                "cancel_reason": CancelReason.USER.value,
                "cancelled_at": now,
                "updated_by": scope.actor_user_id,
            },
        ):
            raise InvalidStatusTransitionError(
                "Only a scheduled or sending campaign can be cancelled"
            )
        await self.repository.skip_pending_recipients(
            campaign.id, SkipReason.CANCELLED.value
        )
        await self.repository.refresh(campaign)
        await self._settle_credits(campaign)
        await self._audit(
            scope,
            AuditAction.MARKETING_CAMPAIGN_CANCELLED,
            entity_type="marketing_campaign",
            entity_id=campaign.id,
            organization_id=scope.organization_id,
            description=f"Marketing campaign '{campaign.name}' cancelled",
        )
        return await self.campaign_detail(campaign)

    # ======================================================================
    # Delivery logs (§5.6)
    # ======================================================================

    def _recipient_item(
        self,
        recipient: MarketingCampaignRecipient,
        display_name: str | None,
        location_name: str | None = None,
    ) -> dict[str, Any]:
        location_id = getattr(recipient, "location_id", None)
        return {
            "id": str(recipient.id),
            "guest_id": str(recipient.guest_id) if recipient.guest_id else None,
            "display_name": display_name,
            "location_id": str(location_id) if location_id else None,
            "location_name": location_name,
            "masked_address": mask_address(recipient.channel, recipient.address)
            if recipient.address
            else None,
            "status": recipient.status,
            "skip_reason": recipient.skip_reason,
            "error_code": recipient.error_code,
            "error_message": (recipient.error_message or "")[:200] or None,
            "attempt_count": recipient.attempt_count,
            "provider_source": getattr(recipient, "provider_source", None),
            "submitted_at": utc_iso(recipient.submitted_at),
            "delivered_at": utc_iso(recipient.delivered_at),
            "failed_at": utc_iso(recipient.failed_at),
            "charged_minor": None,
        }

    async def _with_charges(
        self, organization_id: uuid.UUID, items: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """``charged_minor`` on recipient/delivery rows (§13.7): the
        recipient's debit, null when it was not charged."""
        if self.credits is None or not items:
            return items
        charges = await self.credits.recipient_charges(
            organization_id, [uuid.UUID(item["id"]) for item in items]
        )
        for item in items:
            item["charged_minor"] = charges.get(uuid.UUID(item["id"]))
        return items

    async def list_recipients(
        self,
        scope: CallerScope,
        campaign_id: uuid.UUID,
        *,
        statuses: list[str] | None,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        campaign = await self._get_campaign(scope, campaign_id)
        rows, meta = await self.repository.list_recipients(
            organization_id=scope.organization_id,
            campaign_id=campaign.id,
            scope_location_id=scope.location_id,
            statuses=statuses,
            channel=None,
            created_from=None,
            created_before=None,
            page=page,
            page_size=page_size,
        )
        items = [
            self._recipient_item(r, name, location_name)
            for r, _c, name, location_name in rows
        ]
        return await self._with_charges(scope.organization_id, items), meta

    async def list_deliveries(
        self,
        scope: CallerScope,
        *,
        channel: Channel | None,
        statuses: list[str] | None,
        campaign_id: uuid.UUID | None,
        date_from: date | None,
        date_to: date | None,
        page: int,
        page_size: int,
        location_id: uuid.UUID | None = None,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        self._guard(scope)
        venue = await self._venue_filter(scope, location_id)
        organization = await self._organization(scope.organization_id)
        zone = self._zone(organization)

        def _start(day: date) -> datetime:
            return datetime(day.year, day.month, day.day, tzinfo=zone).astimezone(UTC)

        rows, meta = await self.repository.list_recipients(
            organization_id=scope.organization_id,
            campaign_id=campaign_id,
            scope_location_id=scope.location_id,
            statuses=statuses,
            channel=channel.value if channel else None,
            created_from=_start(date_from) if date_from else None,
            created_before=_start(date_to + timedelta(days=1)) if date_to else None,
            page=page,
            page_size=page_size,
            venue_location_id=venue,
        )
        items = []
        for recipient, campaign, name, location_name in rows:
            item = self._recipient_item(recipient, name, location_name)
            item["campaign"] = {"id": str(campaign.id), "name": campaign.name}
            item["channel"] = recipient.channel
            items.append(item)
        return await self._with_charges(scope.organization_id, items), meta

    # ======================================================================
    # Public unsubscribe (§5.7)
    # ======================================================================

    async def unsubscribe_info(self, token: str) -> dict[str, Any]:
        recipient = await self.repository.get_recipient_by_token(token)
        if recipient is None:
            raise InvalidTokenError("This unsubscribe link is not valid")
        organization = await self._organization(recipient.organization_id)
        channel = Channel(recipient.channel)
        status = "subscribed"
        if recipient.guest_id is not None:
            consent = (await self.repository.get_consents(recipient.guest_id)).get(
                channel.value
            )
            if consent is None or consent.status == ConsentStatus.OPTED_OUT.value:
                status = "unsubscribed"
        elif recipient.address and await self.repository.is_suppressed(
            recipient.organization_id, channel.value, recipient.address
        ):
            status = "unsubscribed"
        return {
            "venue_name": organization.name,
            "channel": channel.value,
            "masked_address": mask_address(channel, recipient.address)
            if recipient.address
            else None,
            "status": status,
        }

    async def unsubscribe(
        self, token: str, *, ip_address: str | None
    ) -> dict[str, Any]:
        recipient = await self.repository.get_recipient_by_token(token)
        if recipient is None:
            raise InvalidTokenError("This unsubscribe link is not valid")
        guest = (
            await self.repository.get_guest(
                recipient.organization_id, recipient.guest_id
            )
            if recipient.guest_id
            else None
        )
        await self._opt_out(
            organization_id=recipient.organization_id,
            guest=guest,
            channel=Channel(recipient.channel),
            source=ConsentSource.UNSUBSCRIBE_LINK,
            reason=SuppressionReason.UNSUBSCRIBED,
            actor_user_id=None,
            ip_address=ip_address,
            location_id=None,
            now=self._now(),
            address_override=recipient.address,
            source_recipient_id=recipient.id,
        )
        return {"status": "unsubscribed"}

    # ======================================================================
    # Guest-facing consent capture (§5.8)
    # ======================================================================

    async def _entitled(self, organization_id: uuid.UUID) -> bool:
        if self.entitlement_check is None:
            return False
        try:
            return await self.entitlement_check(organization_id)
        except Exception:  # noqa: BLE001 - no license row etc. = not entitled
            logger.info("marketing_entitlement_check_failed", exc_info=True)
            return False

    async def consent_offer(self, *, guest, session) -> dict[str, Any] | None:
        """``marketing_consent_offer`` for the login response: non-null only
        when the venue's portal has the opt-in on, the org is entitled, and
        the guest has no consent row yet."""
        if guest is None or session is None:
            return None
        config = await self.repository.get_portal_config(
            session.organization_id, session.location_id
        )
        if config is None or not config.marketing_consent_enabled:
            return None
        if not await self._entitled(session.organization_id):
            return None
        if await self.repository.has_any_consent(guest.id):
            return None
        organization = await self._organization(session.organization_id)
        view = self._consent_view(config, organization.name)
        return {"text": view["text"], "text_version": view["text_version"]}

    async def record_guest_consent(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
        opt_in: bool,
        consent_text_version: str | None,
        ip_address: str | None,
    ) -> dict[str, Any]:
        from app.domains.guest.constants import GuestSessionStatus

        session = await self.repository.get_session(session_id)
        if (
            session is None
            or session.guest_id != guest_id
            or session.status != GuestSessionStatus.ACTIVE.value
        ):
            raise SessionNotActiveError("The WiFi session is not active for this guest")
        guest = await self.repository.get_guest(session.organization_id, guest_id)
        if guest is None:
            raise SessionNotActiveError("The WiFi session is not active for this guest")
        config = await self.repository.get_portal_config(
            session.organization_id, session.location_id
        )
        if (
            config is None
            or not config.marketing_consent_enabled
            or not await self._entitled(session.organization_id)
        ):
            raise ConsentNotOfferedError("This venue does not offer marketing opt-in")
        current_version = (
            config.marketing_consent_text_version or DEFAULT_CONSENT_TEXT_VERSION
        )
        if consent_text_version != current_version:
            raise StaleConsentTextError(
                "The opt-in wording changed; please review it again",
                text_version=current_version,
            )
        result: dict[str, str] = {}
        now = self._now()
        for channel in CHANNEL_ORDER:
            address = derive_address(
                channel, identifier=guest.identifier, email=guest.email
            )
            if address.address is None:
                result[channel.value] = CONSENT_STATUS_NONE
                continue
            if not opt_in:
                # Declining is not an opt-out event: record nothing.
                existing = (await self.repository.get_consents(guest.id)).get(
                    channel.value
                )
                result[channel.value] = (
                    existing.status if existing else CONSENT_STATUS_NONE
                )
                continue
            await self.repository.upsert_consent(
                organization_id=session.organization_id,
                guest_id=guest.id,
                channel=channel.value,
                status=ConsentStatus.OPTED_IN.value,
                source=ConsentSource.CAPTIVE_PORTAL.value,
                consent_text_version=current_version,
                location_id=session.location_id,
                ip_address=ip_address,
                actor_user_id=None,
                now=now,
            )
            result[channel.value] = ConsentStatus.OPTED_IN.value
        return {"guest_id": str(guest.id), "channels": result}

    # ======================================================================
    # Worker side (§9)
    # ======================================================================

    async def materialize(self, campaign: MarketingCampaign) -> int:
        """Evaluate the audience *now* (consent, suppression, blocks at send
        time) and insert reachable guests as pending recipients. Idempotent
        through ``uq_mcr_campaign_guest``."""
        audience = AudienceFilter.model_validate(campaign.audience_filter)
        scope = CallerScope(
            organization_id=campaign.organization_id,
            location_id=None,
            actor_user_id=None,
        )
        # A stored filter's location_ids were already resolved against the
        # creator's scope at create/update time; re-validate they still
        # belong to the org (a location may have moved/been deleted).
        preview, reachable = await self.evaluate_audience(scope, audience)
        limit = self.settings.marketing_max_recipients_per_campaign
        reachable = reachable[:limit]
        capped_by_credits = getattr(campaign, "capped_by_credits", 0) or 0
        if self.credits is not None and campaign.recipient_count == 0:
            # §13.4 step 3: fit the reservation to the audience as it is now.
            # ``reachable`` is ordered by last_seen_at desc, so a cap keeps
            # the most recent guests. Never fails the campaign for credits.
            allowed, capped_by_credits = await self.credits.adjust_at_dispatch(
                campaign, len(reachable)
            )
            reachable = reachable[:allowed]
        organization = await self._organization(campaign.organization_id)
        criteria = await self._criteria(scope, audience, organization)
        attributed = await self.repository.attribute_locations(
            organization_id=campaign.organization_id,
            guest_ids=[candidate.guest_id for candidate, _ in reachable],
            location_ids=criteria.location_ids,
            visited_from=criteria.visited_from,
            visited_before=criteria.visited_before,
        )
        snapshot = campaign.template_snapshot or {}
        rows = []
        for candidate, address in reachable:
            token = new_unsubscribe_token()
            values = self._values(
                snapshot,
                campaign.variables or {},
                guest_name=candidate.display_name,
                token=token,
            )
            body_key = {
                "sms": "sms_body",
                "whatsapp": "whatsapp_body",
                "email": "email_subject",
            }[campaign.channel]
            rows.append(
                {
                    "organization_id": campaign.organization_id,
                    "campaign_id": campaign.id,
                    "guest_id": candidate.guest_id,
                    "channel": campaign.channel,
                    "location_id": attributed.get(candidate.guest_id)
                    or campaign.location_id,
                    "address": address,
                    "provider_source": getattr(campaign, "provider_source", "wyfy"),
                    "unsubscribe_token": token,
                    "rendered_preview": render(snapshot.get(body_key), values)[:200]
                    or None,
                }
            )
        inserted = await self.repository.insert_recipients(rows)
        await self.repository.update_campaign_cas(
            campaign,
            expected_status=CampaignStatus.SENDING.value,
            data={
                "exclusion_counts": preview["excluded"],
                "recipient_count": campaign.recipient_count + inserted,
                "count_pending": campaign.count_pending + inserted,
                "capped_by_credits": capped_by_credits,
            },
        )
        if inserted == 0 and campaign.recipient_count == 0:
            await self._finalize(
                campaign, reason_if_failed="No reachable guests at dispatch time"
            )
        return inserted

    async def dispatch_due(self) -> dict[str, int]:
        """Beat task body: start every campaign whose time has come."""
        now = self._now()
        started = cancelled = failed = 0
        for campaign_id in await self.repository.due_campaign_ids(now):
            campaign = await self.repository.get_campaign_for_worker(campaign_id)
            if campaign is None or campaign.status != CampaignStatus.SCHEDULED.value:
                continue
            if not await self._entitled(campaign.organization_id):
                if await self.repository.update_campaign_cas(
                    campaign,
                    expected_status=CampaignStatus.SCHEDULED.value,
                    data={
                        "status": CampaignStatus.CANCELLED.value,
                        "cancel_reason": CancelReason.ADDON_LOCKED.value,
                        "cancelled_at": now,
                        "last_error": "Marketing add-on is locked",
                    },
                ):
                    cancelled += 1
                    await self._settle_credits(campaign)
                continue
            channel = Channel(campaign.channel)
            if getattr(campaign, "provider_source", "wyfy") == "own":
                if not await self._byo_entitled(campaign.organization_id):
                    if await self.repository.update_campaign_cas(
                        campaign,
                        expected_status=CampaignStatus.SCHEDULED.value,
                        data={
                            "status": CampaignStatus.CANCELLED.value,
                            "cancel_reason": "byo_locked",
                            "cancelled_at": now,
                            "last_error": "Own-provider add-on is locked",
                        },
                    ):
                        cancelled += 1
                        await self._settle_credits(campaign)
                    continue
                row, reason = await self._snapshot_row(campaign)
                if row is None:
                    # §12.1 row 1: fail, never fall back to Wyfy.
                    if await self.repository.update_campaign_cas(
                        campaign,
                        expected_status=CampaignStatus.SCHEDULED.value,
                        data={
                            "status": CampaignStatus.FAILED.value,
                            "completed_at": now,
                            "last_error": f"own_provider_unavailable: {reason}"[:500],
                        },
                    ):
                        failed += 1
                        await self._settle_credits(campaign)
                    continue
                status = _own_status(channel, row)
            else:
                status = self.senders.status(channel)
            if not status.configured:
                if await self.repository.update_campaign_cas(
                    campaign,
                    expected_status=CampaignStatus.SCHEDULED.value,
                    data={
                        "status": CampaignStatus.FAILED.value,
                        "completed_at": now,
                        "last_error": f"channel_not_configured: {status.reason}"[:500],
                    },
                ):
                    failed += 1
                    await self._settle_credits(campaign)
                continue
            if not await self.repository.update_campaign_cas(
                campaign,
                expected_status=CampaignStatus.SCHEDULED.value,
                data={"status": CampaignStatus.SENDING.value, "started_at": now},
            ):
                continue
            try:
                await self.materialize(campaign)
            except MarketingError as exc:
                await self.repository.update_campaign_cas(
                    campaign,
                    expected_status=CampaignStatus.SENDING.value,
                    data={
                        "status": CampaignStatus.FAILED.value,
                        "completed_at": now,
                        "last_error": f"{exc.data.get('error_code')}: {exc.message}"[
                            :500
                        ],
                    },
                )
                failed += 1
                await self._settle_credits(campaign)
                continue
            await self.repository.commit()
            self._enqueue(campaign.id, 0)
            started += 1
        # "no_worker": a campaign whose first batch never started.
        for campaign in await self.repository.sending_campaigns_without_progress(
            now - timedelta(minutes=10)
        ):
            if await self.repository.update_campaign_cas(
                campaign,
                expected_status=CampaignStatus.SENDING.value,
                data={
                    "status": CampaignStatus.FAILED.value,
                    "completed_at": now,
                    "last_error": "no_worker",
                },
            ):
                await self.repository.skip_pending_recipients(
                    campaign.id, SkipReason.CANCELLED.value
                )
                await self._settle_credits(campaign)
                failed += 1
        await self.repository.commit()
        return {"started": started, "cancelled": cancelled, "failed": failed}

    async def send_batch(self, campaign_id: uuid.UUID) -> dict[str, Any]:
        """One batch of at most ``SEND_BATCH_SIZE`` recipients. Returns
        ``{"requeue": seconds | None, ...}`` for the task wrapper."""
        campaign = await self.repository.get_campaign_for_worker(campaign_id)
        if campaign is None or campaign.status != CampaignStatus.SENDING.value:
            return {"requeue": None, "reason": "not_sending"}
        channel = Channel(campaign.channel)
        now = self._now()
        if channel in QUIET_HOURS_CHANNELS:
            organization = await self._organization(campaign.organization_id)
            zone = self._zone(organization)
            start = self.settings.marketing_quiet_hours_start
            end = self.settings.marketing_quiet_hours_end
            if in_quiet_hours(now, start=start, end=end, zone=zone):
                resume = next_allowed_at(now, start=start, end=end, zone=zone)
                await self.repository.update_campaign_cas(
                    campaign,
                    expected_status=CampaignStatus.SENDING.value,
                    data={"paused_until": resume},
                )
                await self.repository.commit()
                return {
                    "requeue": int((resume - now).total_seconds()) + 1,
                    "reason": "quiet_hours",
                }
        if campaign.paused_until is not None:
            await self.repository.update_campaign_cas(
                campaign,
                expected_status=CampaignStatus.SENDING.value,
                data={"paused_until": None},
            )
        own: OwnSenders | None = None
        own_row = None
        if getattr(campaign, "provider_source", "wyfy") == "own":
            own_row, reason = await self._snapshot_row(campaign)
            if own_row is None:
                # The row this campaign was snapshotted to is gone, disabled
                # or tripped by another campaign: fail what is left. Nothing
                # is ever re-sent through Wyfy.
                prefix = (
                    "own_provider_failed"
                    if reason.startswith("provider failed")
                    else "own_provider_unavailable"
                )
                await self._abort_own(campaign, f"{prefix}: {reason}", reason)
                return {"requeue": None, "reason": prefix}
            own = self.own_sender_factory(own_row)
        claimed = await self.repository.claim_batch(campaign.id, SEND_BATCH_SIZE, now)
        await self.repository.commit()
        snapshot = campaign.template_snapshot or {}
        transient = 0
        for index, recipient in enumerate(claimed):
            try:
                outcome = await self._send_one(
                    campaign, channel, snapshot, recipient, own=own
                )
            except _OwnProviderTripped as trip:
                await self._trip_own(
                    campaign,
                    own_row,
                    trip.reason,
                    unsent_claimed=[r.id for r in claimed[index:]],
                )
                return {"requeue": None, "reason": "own_provider_failed"}
            if outcome == "transient":
                transient += 1
            await self.repository.commit()
        await self.repository.refresh(campaign)
        if campaign.status != CampaignStatus.SENDING.value:
            # Cancelled or locked mid-batch: the claimed rows this batch
            # skipped no longer need their hold.
            await self._settle_credits(campaign)
            await self.repository.commit()
            return {"requeue": None, "reason": "not_sending"}
        remaining = await self.repository.count_pending(campaign.id)
        if remaining:
            max_attempt = max((r.attempt_count for r in claimed), default=1)
            return {
                "requeue": 30 * max_attempt if transient else 0,
                "claimed": len(claimed),
            }
        await self.repository.refresh(campaign)
        if campaign.status == CampaignStatus.SENDING.value:
            await self._finalize(campaign)
            await self.repository.commit()
        return {"requeue": None, "claimed": len(claimed)}

    async def _send_one(
        self,
        campaign: MarketingCampaign,
        channel: Channel,
        snapshot: dict[str, Any],
        recipient: MarketingCampaignRecipient,
        *,
        own: OwnSenders | None = None,
    ) -> str:
        now = self._now()
        # Cancel takes effect between messages.
        await self.repository.refresh(campaign)
        if campaign.status != CampaignStatus.SENDING.value:
            await self.repository.update_recipient(
                recipient.id,
                status=RecipientStatus.SKIPPED.value,
                skip_reason=SkipReason.CANCELLED.value,
            )
            await self.repository.adjust_counters(campaign.id, pending=-1, skipped=1)
            return "skipped"
        skip = await self._recheck_recipient(campaign, channel, recipient)
        if skip is not None:
            await self.repository.update_recipient(
                recipient.id, status=RecipientStatus.SKIPPED.value, skip_reason=skip
            )
            await self.repository.adjust_counters(campaign.id, pending=-1, skipped=1)
            return "skipped"
        guest = (
            await self.repository.get_guest(
                campaign.organization_id, recipient.guest_id
            )
            if recipient.guest_id
            else None
        )
        values = self._values(
            snapshot,
            campaign.variables or {},
            guest_name=guest.display_name if guest else None,
            token=recipient.unsubscribe_token,
        )
        await self.rate_limiter.acquire(
            channel,
            own_organization_id=campaign.organization_id if own else None,
            own_rate=self.settings.marketing_own_rate_per_sec,
        )
        try:
            result, preview = await self._deliver(
                channel, snapshot, values, recipient.address or "", own=own
            )
        except SendError as exc:
            if own is not None:
                exc.message = own.scrubber(exc.message) or ""
                if exc.auth:
                    # §12.1 row 2: the venue's account refused our
                    # credentials. Stop; nothing goes through Wyfy.
                    raise _OwnProviderTripped(exc.message) from exc
            if not exc.permanent and recipient.attempt_count < SEND_MAX_ATTEMPTS:
                await self.repository.update_recipient(
                    recipient.id,
                    status=RecipientStatus.PENDING.value,
                    error_code=exc.code,
                    error_message=exc.message,
                    next_attempt_at=now
                    + timedelta(seconds=30 * recipient.attempt_count),
                )
                return "transient"
            await self.repository.update_recipient(
                recipient.id,
                status=RecipientStatus.FAILED.value,
                error_code=exc.code,
                error_message=exc.message,
                failed_at=now,
            )
            await self.repository.adjust_counters(campaign.id, pending=-1, failed=1)
            if exc.suppress_reason and recipient.address:
                await self.repository.add_suppression(
                    organization_id=campaign.organization_id,
                    channel=channel.value,
                    address_normalized=recipient.address,
                    reason=exc.suppress_reason,
                    source_recipient_id=recipient.id,
                )
            return "failed"
        await self.repository.update_recipient(
            recipient.id,
            status=RecipientStatus.SUBMITTED.value,
            provider=result.provider,
            provider_source="own" if own is not None else "wyfy",
            provider_message_id=result.message_id,
            submitted_at=now,
            rendered_preview=preview,
            error_code=None,
            error_message=None,
        )
        await self.repository.adjust_counters(campaign.id, pending=-1, submitted=1)
        if self.credits is not None and own is None:
            # §13.4 step 4: in the same transaction as "submitted" (the
            # caller commits both), after the campaign-row update so every
            # writer takes the campaign row before the wallet row.
            await self.credits.debit_recipient(
                campaign,
                recipient.id,
                actual_units(channel, snapshot, values, test=False),
            )
        return "submitted"

    async def _recheck_recipient(
        self,
        campaign: MarketingCampaign,
        channel: Channel,
        recipient: MarketingCampaignRecipient,
    ) -> str | None:
        """A guest who unsubscribed a minute ago is skipped, even mid-campaign."""
        if not recipient.address:
            return SkipReason.INVALID_ADDRESS.value
        if recipient.guest_id is not None:
            guest = await self.repository.get_guest(
                campaign.organization_id, recipient.guest_id
            )
            if guest is None:
                return SkipReason.NO_CONSENT.value
            if guest.is_blocked:
                return SkipReason.BLOCKED.value
            consent = (await self.repository.get_consents(recipient.guest_id)).get(
                channel.value
            )
            if consent is None:
                return SkipReason.NO_CONSENT.value
            if consent.status != ConsentStatus.OPTED_IN.value:
                return SkipReason.OPTED_OUT.value
        if await self.repository.is_suppressed(
            campaign.organization_id, channel.value, recipient.address
        ):
            return SkipReason.SUPPRESSED.value
        return None

    async def _abort_own(
        self,
        campaign: MarketingCampaign,
        last_error: str,
        reason: str,
        *,
        unsent_claimed: list[uuid.UUID] | None = None,
    ) -> None:
        await self.repository.fail_unsent_recipients(
            campaign.id,
            error_code="own_provider_failed",
            error_message=reason,
            claimed_ids=unsent_claimed or [],
        )
        await self._finalize(campaign, last_error=last_error)
        await self.repository.commit()

    async def _trip_own(
        self,
        campaign: MarketingCampaign,
        row: Any,
        reason: str,
        *,
        unsent_claimed: list[uuid.UUID],
    ) -> None:
        """Auth-class error from the venue's own provider: trip the row to
        ``failed`` once (compare-and-set), fail the current and every
        remaining recipient with ``own_provider_failed``, finalize. Other
        campaigns on the row fail at their next batch."""
        tripped = await self.repository.trip_provider(row.id, reason)
        if tripped:
            await self._audit(
                None,
                AuditAction.MARKETING_PROVIDER_TRIPPED,
                entity_type="org_marketing_provider",
                entity_id=row.id,
                organization_id=campaign.organization_id,
                description=f"Own {row.channel} provider failed authentication",
                metadata={"campaign_id": str(campaign.id)},
            )
        await self._abort_own(
            campaign,
            f"own_provider_failed: {reason}",
            reason,
            unsent_claimed=unsent_claimed,
        )

    async def _finalize(
        self,
        campaign: MarketingCampaign,
        *,
        reason_if_failed: str | None = None,
        last_error: str | None = None,
    ) -> None:
        await self.repository.refresh(campaign)
        if campaign.status != CampaignStatus.SENDING.value:
            return
        now = self._now()
        if campaign.count_submitted > 0:
            data = {"status": CampaignStatus.SENT.value, "completed_at": now}
            if last_error:
                data["last_error"] = last_error[:500]
        else:
            data = {
                "status": CampaignStatus.FAILED.value,
                "completed_at": now,
                "last_error": (
                    last_error
                    or reason_if_failed
                    or "No message was accepted by the provider"
                )[:500],
            }
        if await self.repository.update_campaign_cas(
            campaign, expected_status=CampaignStatus.SENDING.value, data=data
        ):
            await self._settle_credits(campaign)

    async def _settle_credits(self, campaign: MarketingCampaign) -> None:
        """§13.4 step 6: a terminal campaign releases what it still holds,
        except the share of recipients a worker is still sending (released
        by that worker's batch once they settle)."""
        if self.credits is None:
            return
        in_flight = await self.repository.count_in_flight(campaign.id)
        await self.credits.settle(campaign, in_flight)

    async def reap_stuck(self) -> dict[str, int]:
        now = self._now()
        campaign_ids = await self.repository.reap_stuck_recipients(
            now - timedelta(minutes=STALE_SENDING_MINUTES)
        )
        finalized = 0
        for campaign_id in campaign_ids:
            campaign = await self.repository.get_campaign_for_worker(campaign_id)
            if campaign is None:
                continue
            if await self.repository.count_pending(campaign.id) == 0:
                await self._finalize(campaign)
                finalized += 1
            # worker_lost recipients are never charged: once the campaign is
            # terminal, their hold goes back to available.
            await self._settle_credits(campaign)
        await self.repository.commit()
        return {"campaigns": len(campaign_ids), "finalized": finalized}

    async def prune_recipient_pii(self) -> int:
        count = await self.repository.prune_recipient_pii(
            self._now() - timedelta(days=RECIPIENT_ADDRESS_RETENTION_DAYS)
        )
        await self.repository.commit()
        return count


def _bump_version(current: str) -> str:
    if current.startswith("v") and current[1:].isdigit():
        return f"v{int(current[1:]) + 1}"
    return f"{current}.1"


__all__ = ["CallerScope", "MarketingService"]

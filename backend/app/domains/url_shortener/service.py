"""URL Shortener business logic: code generation, create (all three
sources), read/list/update/revoke (org-scoped and master/cross-tenant),
and the guest-facing redirect's click recording.

Design notes worth calling out up front (see ``models.py``'s module
docstring for the create-source/tenant-scoping write-up and
``validators.py``'s for the target-URL validation scope):

## Tenant isolation

Every org-scoped read/write (``get_short_link``/``update_short_link``/
``revoke_short_link``/``list_short_links``) takes a
``requesting_organization_id`` the same way every other domain's own
service does (``VoucherService.get_batch``, ``LocationService
.get_location``, ...): ``None`` means a platform-level (GLOBAL-scoped)
caller acting with no tenant filter (used by the Master-console surface);
a real UUID means "this row must belong to exactly this organization or
raise ``CrossOrganizationShortLinkAccessError``". A link created
anonymously (``organization_id is None``, ``source=public_site``) can
never be read/updated/revoked through the org-scoped surface at all -- a
tenant-scoped caller's own organization_id is never ``None``, so the
equality check on a ``None``-owned row always fails closed (403), which is
the correct behavior: an anonymous link belongs to no tenant, only to the
Master console's own moderation surface.

## Guest-facing (public-create + redirect) rate limiting

Both ``create_public_short_link`` and ``resolve_and_record_click`` are
guarded by ``ShortLinkRateLimiter``, a Redis-backed, per-``source`` (the
caller's presumed IP address, supplied by ``router.py``) INCR+EXPIRE+TTL
throttle -- the identical mechanism
``app.domains.voucher.service.VoucherRedemptionRateLimiter``/
``app.domains.otp.service.OtpRateLimiter`` already established, reused in
shape (not literally shared code, since each protects a different
resource key) rather than reinvented. The two are rate-limited under
separate keys/budgets -- see ``constants.py``'s own module docstring for
why.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import choice as secrets_choice
from typing import Protocol

from redis.asyncio import Redis

from app.domains.rbac.enums import AuditAction

from .constants import (
    CODE_GENERATION_MAX_ROUNDS,
    SHORT_LINK_CODE_ALPHABET,
    SHORT_LINK_CODE_LENGTH,
    SHORT_LINK_CREATE_RATE_LIMIT_KEY_TEMPLATE,
    SHORT_LINK_REDIRECT_RATE_LIMIT_KEY_TEMPLATE,
    ShortLinkSource,
)
from .exceptions import (
    CrossOrganizationShortLinkAccessError,
    ShortLinkCodeGenerationExhaustedError,
    ShortLinkCreateRateLimitExceededError,
    ShortLinkNotFoundError,
    ShortLinkRedirectRateLimitExceededError,
)
from .models import ShortLink
from .repository import ShortLinkRepositoryProtocol
from .validators import validate_target_url

logger = logging.getLogger(__name__)


# ============================================================================
# Rate limiting
# ============================================================================


class ShortLinkRateLimiter:
    """Static-method facade over Redis for guest-facing public-create and
    redirect rate limiting -- see module docstring."""

    @staticmethod
    async def check_and_increment(
        redis: Redis,
        key: str,
        *,
        max_attempts: int,
        window_minutes: int,
        exceeded_exception: type[
            ShortLinkCreateRateLimitExceededError
            | ShortLinkRedirectRateLimitExceededError
        ],
    ) -> None:
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window_minutes * 60)
        if current > max_attempts:
            ttl = await redis.ttl(key)
            raise exceeded_exception(ttl if ttl and ttl > 0 else window_minutes * 60)

    @classmethod
    async def check_create(
        cls, redis: Redis, source: str, *, max_attempts: int, window_minutes: int
    ) -> None:
        key = SHORT_LINK_CREATE_RATE_LIMIT_KEY_TEMPLATE.format(source=source)
        await cls.check_and_increment(
            redis,
            key,
            max_attempts=max_attempts,
            window_minutes=window_minutes,
            exceeded_exception=ShortLinkCreateRateLimitExceededError,
        )

    @classmethod
    async def check_redirect(
        cls, redis: Redis, source: str, *, max_attempts: int, window_minutes: int
    ) -> None:
        key = SHORT_LINK_REDIRECT_RATE_LIMIT_KEY_TEMPLATE.format(source=source)
        await cls.check_and_increment(
            redis,
            key,
            max_attempts=max_attempts,
            window_minutes=window_minutes,
            exceeded_exception=ShortLinkRedirectRateLimitExceededError,
        )


# ============================================================================
# Narrow cross-domain protocol (composition, not duplication)
# ============================================================================


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclass(frozen=True, slots=True)
class ShortLinkListFilters:
    organization_id: uuid.UUID | None = None
    source: str | None = None
    is_active: bool | None = None


class ShortLinkService:
    """Core URL Shortener business logic."""

    def __init__(
        self,
        repository: ShortLinkRepositoryProtocol,
        redis: Redis,
        *,
        audit_writer: AuditLogWriter | None = None,
        create_max_attempts_per_window: int,
        create_window_minutes: int,
        redirect_max_attempts_per_window: int,
        redirect_window_minutes: int,
    ) -> None:
        self.repository = repository
        self.redis = redis
        self.audit_writer = audit_writer
        self.create_max_attempts_per_window = create_max_attempts_per_window
        self.create_window_minutes = create_window_minutes
        self.redirect_max_attempts_per_window = redirect_max_attempts_per_window
        self.redirect_window_minutes = redirect_window_minutes

    # ========================================================================
    # Code generation
    # ========================================================================

    async def _generate_code(self) -> str:
        """Generates one collision-checked, ~7-char base62 code -- retries
        (in-memory candidate + a fresh DB-existence check each round) up to
        ``CODE_GENERATION_MAX_ROUNDS`` times, mirroring
        ``app.domains.voucher.service.VoucherService._generate_codes``'s
        identical retry-then-verify shape (adapted to a single code, since
        this module creates one ``ShortLink`` per call, not a bulk batch)."""
        for _ in range(CODE_GENERATION_MAX_ROUNDS):
            candidate = "".join(
                secrets_choice(SHORT_LINK_CODE_ALPHABET)
                for _ in range(SHORT_LINK_CODE_LENGTH)
            )
            existing = await self.repository.find_existing_codes([candidate])
            if not existing:
                return candidate
        raise ShortLinkCodeGenerationExhaustedError()

    # ========================================================================
    # Create
    # ========================================================================

    async def _create(
        self,
        *,
        target_url: str,
        source: ShortLinkSource,
        organization_id: uuid.UUID | None,
        created_by_user_id: uuid.UUID | None,
        expires_at: datetime | None,
    ) -> ShortLink:
        validated_url = validate_target_url(target_url)
        code = await self._generate_code()
        short_link = await self.repository.create(
            code=code,
            target_url=validated_url,
            organization_id=organization_id,
            created_by_user_id=created_by_user_id,
            source=source.value,
            click_count=0,
            last_clicked_at=None,
            is_active=True,
            expires_at=expires_at,
            created_by=created_by_user_id,
        )
        logger.info(
            "short_link_created",
            extra={
                "short_link_id": str(short_link.id),
                "source": source.value,
                "organization_id": str(organization_id) if organization_id else None,
            },
        )
        # See app.domains.rbac.enums.AuditAction's own SHORT_LINK_CREATED
        # docstring: only a customer/master-sourced create is audited --
        # the high-volume, unauthenticated public_site create is not,
        # mirroring OTP's identical audit-volume judgment call.
        if source != ShortLinkSource.PUBLIC_SITE and self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=created_by_user_id,
                action=AuditAction.SHORT_LINK_CREATED.value,
                entity_type="short_link",
                entity_id=short_link.id,
                description=f"Short link '{short_link.code}' created",
                event_metadata={"source": source.value},
                organization_id=organization_id,
                location_id=None,
            )
        return short_link

    async def create_public_short_link(
        self, *, target_url: str, source_ip: str, expires_at: datetime | None = None
    ) -> ShortLink:
        """``POST /api/v1/public/short-links`` -- anonymous, no auth. See
        module docstring for the rate-limit reasoning."""
        await ShortLinkRateLimiter.check_create(
            self.redis,
            source_ip,
            max_attempts=self.create_max_attempts_per_window,
            window_minutes=self.create_window_minutes,
        )
        return await self._create(
            target_url=target_url,
            source=ShortLinkSource.PUBLIC_SITE,
            organization_id=None,
            created_by_user_id=None,
            expires_at=expires_at,
        )

    async def create_customer_short_link(
        self,
        *,
        target_url: str,
        organization_id: uuid.UUID,
        created_by_user_id: uuid.UUID | None,
        expires_at: datetime | None = None,
    ) -> ShortLink:
        """``POST /api/v1/short-links`` -- authenticated, org-scoped."""
        return await self._create(
            target_url=target_url,
            source=ShortLinkSource.CUSTOMER,
            organization_id=organization_id,
            created_by_user_id=created_by_user_id,
            expires_at=expires_at,
        )

    # ========================================================================
    # Read / list (org-scoped and master/cross-tenant, via
    # requesting_organization_id=None)
    # ========================================================================

    async def get_short_link(
        self,
        short_link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> ShortLink:
        short_link = await self.repository.get_by_id(short_link_id)
        if short_link is None or short_link.is_deleted:
            raise ShortLinkNotFoundError(short_link_id)
        if (
            requesting_organization_id is not None
            and short_link.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationShortLinkAccessError()
        return short_link

    async def list_short_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        extra_filters: ShortLinkListFilters | None = None,
    ) -> tuple[list[ShortLink], object]:
        """Org-scoped when ``requesting_organization_id`` is a real UUID
        (the customer-dashboard surface, ``GET /api/v1/short-links``);
        unscoped (subject only to ``extra_filters``) when ``None`` (the
        Master-console cross-tenant surface,
        ``GET /api/v1/master/short-links``)."""
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        elif extra_filters is not None and extra_filters.organization_id is not None:
            filters["organization_id"] = extra_filters.organization_id
        if extra_filters is not None:
            if extra_filters.source is not None:
                filters["source"] = extra_filters.source
            if extra_filters.is_active is not None:
                filters["is_active"] = extra_filters.is_active
        return await self.repository.list_short_links(
            page=page, page_size=page_size, filters=filters or None
        )

    # ========================================================================
    # Update / revoke
    # ========================================================================

    async def update_short_link(
        self,
        short_link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> ShortLink:
        """``PATCH /api/v1/short-links/{id}`` -- ``data`` is expected to
        already be exactly the caller-provided fields (router layer:
        ``ShortLinkUpdateRequest.model_dump(exclude_unset=True)``), so an
        explicit ``target_url`` re-validates through the same
        ``validate_target_url`` gate creation uses -- there is no separate,
        weaker path to sneak a ``javascript:``/internal-host URL past
        creation-time validation via a later update."""
        short_link = await self.get_short_link(
            short_link_id, requesting_organization_id=requesting_organization_id
        )
        update_data = dict(data)
        if "target_url" in update_data and update_data["target_url"] is not None:
            update_data["target_url"] = validate_target_url(
                str(update_data["target_url"])
            )
        return await self.repository.update(short_link, update_data)

    async def revoke_short_link(
        self,
        short_link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None = None,
    ) -> ShortLink:
        """``DELETE /api/v1/short-links/{id}`` -- soft revoke: sets
        ``is_active=False``, following this codebase's own "a
        business-status toggle, not ``BaseModel.mark_deleted``'s row-level
        soft-delete" convention for a lifecycle revoke (mirrors
        ``VoucherService.revoke_batch``, which flips ``VoucherBatch.status``
        to ``REVOKED`` rather than soft-deleting the row -- the row must
        stay fully readable/listable afterward, e.g. for the org's own
        history view and the Master console's moderation view, exactly as
        this module's own contract requires)."""
        short_link = await self.get_short_link(
            short_link_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update(short_link, {"is_active": False})
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AuditAction.SHORT_LINK_REVOKED.value,
                entity_type="short_link",
                entity_id=updated.id,
                description=f"Short link '{updated.code}' revoked",
                event_metadata={},
                organization_id=updated.organization_id,
                location_id=None,
            )
        return updated

    async def master_moderate_short_link(
        self, short_link_id: uuid.UUID, *, data: dict[str, object]
    ) -> ShortLink:
        """``PATCH /api/v1/master/short-links/{id}`` -- platform-operator
        moderation of *any* organization's (or anonymous) link, for abuse
        handling. Deliberately takes no ``requesting_organization_id`` at
        all (unlike ``update_short_link``) -- a Master-console caller's
        entire point is cross-tenant reach; RBAC's own
        ``scope=ScopeType.GLOBAL`` pin on this route (see ``router.py``) is
        what already restricts who may call it, not a second, redundant
        tenant check here."""
        short_link = await self.repository.get_by_id(short_link_id)
        if short_link is None or short_link.is_deleted:
            raise ShortLinkNotFoundError(short_link_id)
        updated = await self.repository.update(short_link, dict(data))
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=None,
                action=AuditAction.SHORT_LINK_MODERATED.value,
                entity_type="short_link",
                entity_id=updated.id,
                description=f"Short link '{updated.code}' moderated by Master console",
                event_metadata={"fields": sorted(data.keys())},
                organization_id=updated.organization_id,
                location_id=None,
            )
        return updated

    # ========================================================================
    # Guest-facing redirect
    # ========================================================================

    async def resolve_and_record_click(
        self, code: str, *, source_ip: str
    ) -> ShortLink:
        """``GET /api/v1/s/{code}`` -- looks up ``code``, atomically records
        the click (see ``repository.ShortLinkRepository.record_click``'s own
        docstring for the concurrency-safety write-up), and returns the
        resolved ``ShortLink`` for ``router.py`` to redirect to. Raises
        ``ShortLinkNotFoundError`` for not-found/inactive/expired alike --
        see ``exceptions.py``'s module docstring for why these are
        deliberately collapsed into one 404 for this guest-facing path."""
        await ShortLinkRateLimiter.check_redirect(
            self.redis,
            source_ip,
            max_attempts=self.redirect_max_attempts_per_window,
            window_minutes=self.redirect_window_minutes,
        )
        now = datetime.now(UTC)
        short_link = await self.repository.record_click(code.strip(), now=now)
        if short_link is None:
            raise ShortLinkNotFoundError()
        return short_link


__all__ = [
    "ShortLinkService",
    "ShortLinkRateLimiter",
    "ShortLinkListFilters",
    "AuditLogWriter",
]

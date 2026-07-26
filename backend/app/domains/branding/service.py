"""Branding business logic: get/update per-organization branding, with
default fallback."""

from __future__ import annotations

import logging
import uuid
from typing import Protocol

from app.core.storage import ObjectStorageError, ObjectStorageProtocol

from .exceptions import (
    BackgroundImageNotFoundError,
    BrandingStorageNotConfiguredError,
    InvalidBackgroundImageError,
    InvalidLogoError,
    LogoNotFoundError,
)
from .models import Branding
from .repository import BrandingRepositoryProtocol
from .schemas import BrandingResponse, BrandingUpdateRequest, DefaultBrandingResponse

logger = logging.getLogger(__name__)

DEFAULT_BRANDING = DefaultBrandingResponse()

# Background image upload constraints for the customer dashboard's
# Background Image page (login-screen background). Kept intentionally
# small/conservative -- there is no image processing/resizing pipeline in
# this module, the raw bytes are stored and served as-is.
BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES: dict[str, str] = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}
BACKGROUND_IMAGE_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB

# The path BrandingResponse.background_image_url points browsers at --
# proxied through this API (see get_background_image_bytes / the router's
# GET /branding/background-image/raw) rather than a direct object-storage
# link. A presigned MinIO/S3 URL would need that storage endpoint itself
# reachable from the browser, which on this platform's actual single-VM
# deployment it deliberately isn't (only the API's own port is opened) --
# real AWS S3 in another deployment would make a direct link *possible*,
# but routing every deployment through the already-authenticated,
# already-public API is simpler than conditioning behavior on which one
# this happens to be.
BACKGROUND_IMAGE_RAW_PATH = "/branding/background-image/raw"

_EXTENSION_TO_CONTENT_TYPE = {
    ext: content_type
    for content_type, ext in BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES.items()
}

# Logo upload constraints -- same allowed types/size ceiling as the
# background image (no image-processing pipeline exists here either), a
# separate constant only so the two can diverge later without coupling.
LOGO_ALLOWED_CONTENT_TYPES: dict[str, str] = dict(
    BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES
)
LOGO_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB

# See BACKGROUND_IMAGE_RAW_PATH's own comment -- same reasoning, same
# same-API-proxy-not-direct-object-storage-link approach.
LOGO_RAW_PATH = "/branding/logo/raw"

# Unauthenticated counterparts (see GET /branding/{organization_id}/logo/public
# and .../background-image/public's own docstrings) -- what
# app.domains.captive_portal's guest-facing resolve endpoint points a
# real guest's browser at when a location's own captive_portal_configs
# row has no logo_url/background_image_url of its own set, falling back
# to the organization's branding upload. `{organization_id}` is filled in
# by the caller (there is no session to derive it from at that call site
# either).
PUBLIC_LOGO_PATH_TEMPLATE = "/branding/{organization_id}/logo/public"
PUBLIC_BACKGROUND_IMAGE_PATH_TEMPLATE = (
    "/branding/{organization_id}/background-image/public"
)


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class BrandingService:
    def __init__(
        self,
        repository: BrandingRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        object_storage: ObjectStorageProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer
        self.object_storage = object_storage

    async def get_branding(self, organization_id: uuid.UUID) -> BrandingResponse:
        branding = await self.repository.get_by_organization(organization_id)
        if branding is None:
            return DEFAULT_BRANDING
        return await self._to_response(branding)

    async def update_branding(
        self,
        organization_id: uuid.UUID,
        data: BrandingUpdateRequest,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        update_data = data.model_dump(exclude_unset=True, exclude_none=True)
        branding = await self.repository.upsert(
            organization_id, update_data, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Branding updated for organization {organization_id}",
            organization_id=organization_id,
        )
        return await self._to_response(branding)

    async def upload_background_image(
        self,
        organization_id: uuid.UUID,
        *,
        filename: str,
        content_type: str,
        content: bytes,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        """Uploads a new login-screen background image for ``organization_id``,
        replacing any existing one, and persists the storage key.

        Reuses ``app.core.storage`` -- the same object storage
        ``app.domains.voucher``/``app.domains.analytics`` already write
        through -- rather than inventing a new storage mechanism.
        """
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        extension = BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES.get(content_type)
        if extension is None:
            raise InvalidBackgroundImageError(
                f"unsupported content type '{content_type}' -- allowed: "
                f"{', '.join(sorted(BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES))}"
            )
        if not content:
            raise InvalidBackgroundImageError("uploaded file is empty")
        if len(content) > BACKGROUND_IMAGE_MAX_BYTES:
            max_mb = BACKGROUND_IMAGE_MAX_BYTES // (1024 * 1024)
            raise InvalidBackgroundImageError(f"file exceeds the {max_mb}MB limit")

        key = f"branding/{organization_id}/background/{uuid.uuid4()}.{extension}"
        try:
            await self.object_storage.upload(
                key=key, content=content, content_type=content_type
            )
        except ObjectStorageError:
            logger.exception(
                "background_image_upload_failed",
                extra={"organization_id": str(organization_id)},
            )
            raise

        branding = await self.repository.set_background_image_key(
            organization_id, key, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_background_image_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=(
                f"Background image updated for organization {organization_id} "
                f"(original filename: {filename})"
            ),
            organization_id=organization_id,
        )
        return await self._to_response(branding)

    async def delete_background_image(
        self,
        organization_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        branding = await self.repository.set_background_image_key(
            organization_id, None, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_background_image_removed",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Background image removed for organization {organization_id}",
            organization_id=organization_id,
        )
        return await self._to_response(branding)

    async def upload_logo(
        self,
        organization_id: uuid.UUID,
        *,
        filename: str,
        content_type: str,
        content: bytes,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        """Uploads a new logo for ``organization_id``, replacing any
        existing one, and persists the storage key. Mirrors
        upload_background_image exactly -- same object storage, same
        validation shape."""
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        extension = LOGO_ALLOWED_CONTENT_TYPES.get(content_type)
        if extension is None:
            raise InvalidLogoError(
                f"unsupported content type '{content_type}' -- allowed: "
                f"{', '.join(sorted(LOGO_ALLOWED_CONTENT_TYPES))}"
            )
        if not content:
            raise InvalidLogoError("uploaded file is empty")
        if len(content) > LOGO_MAX_BYTES:
            max_mb = LOGO_MAX_BYTES // (1024 * 1024)
            raise InvalidLogoError(f"file exceeds the {max_mb}MB limit")

        key = f"branding/{organization_id}/logo/{uuid.uuid4()}.{extension}"
        try:
            await self.object_storage.upload(
                key=key, content=content, content_type=content_type
            )
        except ObjectStorageError:
            logger.exception(
                "logo_upload_failed",
                extra={"organization_id": str(organization_id)},
            )
            raise

        branding = await self.repository.set_logo_key(
            organization_id, key, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_logo_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=(
                f"Logo updated for organization {organization_id} "
                f"(original filename: {filename})"
            ),
            organization_id=organization_id,
        )
        return await self._to_response(branding)

    async def delete_logo(
        self,
        organization_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        branding = await self.repository.set_logo_key(
            organization_id, None, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_logo_removed",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Logo removed for organization {organization_id}",
            organization_id=organization_id,
        )
        return await self._to_response(branding)

    async def get_default_branding(self) -> DefaultBrandingResponse:
        return DEFAULT_BRANDING

    async def get_background_image_bytes(
        self, organization_id: uuid.UUID
    ) -> tuple[bytes, str]:
        """Streams the current background image's raw bytes + content
        type -- backs ``GET /branding/background-image/raw``, the proxy
        endpoint ``background_image_url`` actually points at.

        Raises ``BackgroundImageNotFoundError`` if the organization has
        no background image set, ``BrandingStorageNotConfiguredError`` if
        this service instance has no object storage backend.
        """
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        branding = await self.repository.get_by_organization(organization_id)
        key = branding.background_image_key if branding else None
        if not key:
            raise BackgroundImageNotFoundError(organization_id)

        content = await self.object_storage.download(key=key)
        extension = key.rsplit(".", 1)[-1].lower() if "." in key else ""
        content_type = _EXTENSION_TO_CONTENT_TYPE.get(
            extension, "application/octet-stream"
        )
        return content, content_type

    async def get_logo_bytes(self, organization_id: uuid.UUID) -> tuple[bytes, str]:
        """Streams the current uploaded logo's raw bytes + content type --
        backs ``GET /branding/logo/raw``. Mirrors get_background_image_bytes
        exactly. Raises ``LogoNotFoundError`` if the organization has no
        *uploaded* logo (a plain-text ``logo_url`` with no ``logo_key``
        doesn't count -- that's rendered by hotlinking the URL directly,
        never through this proxy)."""
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        branding = await self.repository.get_by_organization(organization_id)
        key = branding.logo_key if branding else None
        if not key:
            raise LogoNotFoundError(organization_id)

        content = await self.object_storage.download(key=key)
        extension = key.rsplit(".", 1)[-1].lower() if "." in key else ""
        content_type = _EXTENSION_TO_CONTENT_TYPE.get(
            extension, "application/octet-stream"
        )
        return content, content_type

    async def _to_response(self, branding: Branding) -> BrandingResponse:
        logo_url, logo_is_uploaded = self._resolve_logo_url(branding)
        return BrandingResponse(
            id=str(branding.id),
            organization_id=str(branding.organization_id),
            company_name=branding.company_name,
            logo_url=logo_url,
            logo_is_uploaded=logo_is_uploaded,
            favicon_url=branding.favicon_url,
            primary_color=branding.primary_color,
            secondary_color=branding.secondary_color,
            accent_color=branding.accent_color,
            theme=branding.theme or "light",
            background_image_url=await self._resolve_background_image_url(branding),
            created_at=branding.created_at,
            updated_at=branding.updated_at,
        )

    async def _resolve_background_image_url(self, branding: Branding) -> str | None:
        """Turns the durable, persisted ``background_image_key`` into the
        stable proxy path the frontend fetches (authenticated, same as
        every other branding call) to render the actual image -- see
        ``BACKGROUND_IMAGE_RAW_PATH``'s own docstring for why this is a
        same-API proxy path rather than a direct object-storage link."""
        if not branding.background_image_key:
            return None
        return BACKGROUND_IMAGE_RAW_PATH

    def _resolve_logo_url(self, branding: Branding) -> tuple[str | None, bool]:
        """An uploaded logo (``logo_key`` set) always wins over the plain
        text ``logo_url`` column -- returns the stable proxy path and
        ``True`` for that case, or the plain text URL as-is and ``False``
        when there's no upload. See ``BrandingResponse.logo_is_uploaded``'s
        own docstring for why the frontend needs to tell these apart."""
        if branding.logo_key:
            return LOGO_RAW_PATH, True
        return branding.logo_url, False

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: str,
        *,
        entity_type: str,
        entity_id: uuid.UUID | None = None,
        description: str = "",
        organization_id: uuid.UUID | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )

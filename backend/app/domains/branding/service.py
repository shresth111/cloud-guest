"""Branding business logic: get/update per-organization branding, with
default fallback."""

from __future__ import annotations

import logging
import uuid
from typing import Protocol

from app.core.storage import ObjectStorageError, ObjectStorageProtocol

from .exceptions import (
    BrandingStorageNotConfiguredError,
    InvalidBackgroundImageError,
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
BACKGROUND_IMAGE_PRESIGNED_URL_TTL_SECONDS = 3600


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

    async def get_default_branding(self) -> DefaultBrandingResponse:
        return DEFAULT_BRANDING

    async def _to_response(self, branding: Branding) -> BrandingResponse:
        return BrandingResponse(
            id=str(branding.id),
            organization_id=str(branding.organization_id),
            company_name=branding.company_name,
            logo_url=branding.logo_url,
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
        """Turns the durable, persisted ``background_image_key`` into a
        fresh, browser-usable presigned URL -- called on every read so the
        URL's own expiry never matters to callers."""
        key = branding.background_image_key
        if not key:
            return None
        if self.object_storage is None:
            return None
        try:
            return await self.object_storage.generate_presigned_url(
                key=key,
                expires_in_seconds=BACKGROUND_IMAGE_PRESIGNED_URL_TTL_SECONDS,
            )
        except ObjectStorageError:
            logger.exception(
                "background_image_presign_failed",
                extra={"organization_id": str(branding.organization_id)},
            )
            return None

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

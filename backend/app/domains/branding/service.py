"""Branding business logic: get/update per-organization branding with default fallback."""

from __future__ import annotations

import uuid
import logging
from typing import Any, Protocol

from app.domains.rbac.models import AuditLogEntry

from .repository import BrandingRepositoryProtocol
from .schemas import BrandingResponse, BrandingUpdateRequest, DefaultBrandingResponse
from .exceptions import BrandingNotFoundError

logger = logging.getLogger(__name__)

DEFAULT_BRANDING = DefaultBrandingResponse()


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class BrandingService:
    def __init__(
        self,
        repository: BrandingRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def get_branding(
        self, organization_id: uuid.UUID
    ) -> BrandingResponse:
        branding = await self.repository.get_by_organization(organization_id)
        if branding is None:
            return DEFAULT_BRANDING
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
            created_at=branding.created_at,
            updated_at=branding.updated_at,
        )

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
            created_at=branding.created_at,
            updated_at=branding.updated_at,
        )

    async def get_default_branding(self) -> DefaultBrandingResponse:
        return DEFAULT_BRANDING

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

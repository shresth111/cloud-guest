"""Service layer for the Branding domain."""

from __future__ import annotations

import uuid
from .exceptions import BrandingNotFoundError
from .models import Branding
from .repository import BrandingRepositoryProtocol


class BrandingService:
    def __init__(self, repository: BrandingRepositoryProtocol) -> None:
        self.repository = repository

    async def get_branding_for_organization(self, organization_id: uuid.UUID) -> Branding:
        branding = await self.repository.get_by_organization(organization_id)
        if not branding:
            # Create a default blank branding profile
            data = {
                "organization_id": organization_id,
                "company_name": "CloudGuest Tenant",
                "primary_color": "#4F46E5",
                "secondary_color": "#0F172A",
                "typography": "Inter",
                "theme": "light",
            }
            branding = await self.repository.create_branding(data)
        return branding

    async def get_effective_branding(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None = None
    ) -> Branding:
        """Resolve Effective branding cascading from Location level down to Org level."""
        if location_id:
            loc_branding = await self.repository.get_by_location(location_id)
            if loc_branding:
                return loc_branding

        return await self.get_branding_for_organization(organization_id)

    async def update_branding(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None, data: dict
    ) -> Branding:
        if location_id:
            branding = await self.repository.get_by_location(location_id)
            if not branding:
                # Create location-specific branding
                data["organization_id"] = organization_id
                data["location_id"] = location_id
                if "company_name" not in data:
                    data["company_name"] = "Local Brand Branch"
                return await self.repository.create_branding(data)
        else:
            branding = await self.repository.get_by_organization(organization_id)
            if not branding:
                # Create org branding
                data["organization_id"] = organization_id
                if "company_name" not in data:
                    data["company_name"] = "CloudGuest Tenant"
                return await self.repository.create_branding(data)

        return await self.repository.update_branding(branding, data)

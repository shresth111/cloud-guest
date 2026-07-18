"""API Router for the Branding domain."""

import uuid
from fastapi import APIRouter, Depends

from .dependencies import get_branding_service
from .schemas import BrandingResponse, BrandingUpdate
from .service import BrandingService

router = APIRouter()


@router.get("/branding/organization/{organization_id}", response_model=BrandingResponse, tags=["Branding"])
async def get_organization_branding(
    organization_id: uuid.UUID,
    service: BrandingService = Depends(get_branding_service)
):
    """Get the visual customization profiles for an organization."""
    return await service.get_branding_for_organization(organization_id)


@router.get("/branding/resolve", response_model=BrandingResponse, tags=["Branding"])
async def resolve_effective_branding(
    organization_id: uuid.UUID,
    location_id: uuid.UUID | None = None,
    service: BrandingService = Depends(get_branding_service)
):
    """Retrieve effective cascading visual styles for a given location or organization."""
    return await service.get_effective_branding(organization_id, location_id)


@router.put("/branding/organization/{organization_id}", response_model=BrandingResponse, tags=["Branding"])
async def update_branding_profile(
    organization_id: uuid.UUID,
    payload: BrandingUpdate,
    location_id: uuid.UUID | None = None,
    service: BrandingService = Depends(get_branding_service)
):
    """Update primary, secondary colors, logo references, custom footers, and support details."""
    return await service.update_branding(
        organization_id=organization_id,
        location_id=location_id,
        data=payload.model_dump(exclude_unset=True)
    )

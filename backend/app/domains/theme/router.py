"""API Router for the Theme domain."""

import uuid
from fastapi import APIRouter, Depends

from .dependencies import get_theme_service
from .schemas import ThemeResponse, ThemeUpdate
from .service import ThemeService

router = APIRouter()


@router.get("/themes/branding/{branding_id}", response_model=ThemeResponse, tags=["Themes"])
async def get_theme_configuration(
    branding_id: uuid.UUID,
    organization_id: uuid.UUID,
    service: ThemeService = Depends(get_theme_service)
):
    """Retrieve full captive portal layout configurations, background styles, CSS/JS custom codes."""
    return await service.get_theme_by_branding(branding_id, organization_id)


@router.put("/themes/branding/{branding_id}", response_model=ThemeResponse, tags=["Themes"])
async def update_theme_configuration(
    branding_id: uuid.UUID,
    payload: ThemeUpdate,
    service: ThemeService = Depends(get_theme_service)
):
    """Modify the portal landing layout, CSS injections, compliance terms and banner assets."""
    return await service.update_theme(branding_id, payload.model_dump(exclude_unset=True))

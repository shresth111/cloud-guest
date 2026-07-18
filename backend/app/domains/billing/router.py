"""API Router for the Billing domain."""

import uuid
from fastapi import APIRouter, Depends

from .dependencies import get_billing_service
from .service import BillingService
from .schemas import BillingProfileResponse, BillingProfileUpdate

router = APIRouter()


@router.get("/billing/{organization_id}", response_model=BillingProfileResponse, tags=["Billing"])
async def get_billing_profile(
    organization_id: uuid.UUID,
    service: BillingService = Depends(get_billing_service)
):
    """Retrieve billing profile for an organization."""
    return await service.get_or_create_profile(organization_id)


@router.put("/billing/{organization_id}", response_model=BillingProfileResponse, tags=["Billing"])
async def update_billing_profile(
    organization_id: uuid.UUID,
    payload: BillingProfileUpdate,
    service: BillingService = Depends(get_billing_service)
):
    """Update address and billing information for an organization."""
    return await service.update_profile(organization_id, payload.model_dump(exclude_unset=True))

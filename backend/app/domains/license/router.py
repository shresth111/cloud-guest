"""API Router for the License domain."""

import uuid
from typing import Sequence
from fastapi import APIRouter, Depends, status

from .dependencies import get_license_service
from .schemas import (
    LicenseActivateRequest,
    LicenseGenerateRequest,
    LicenseResponse,
    LicenseValidateRequest,
)
from .service import LicenseService

router = APIRouter()


@router.post(
    "/licenses",
    response_model=LicenseResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Licenses"],
)
async def generate_license(
    payload: LicenseGenerateRequest,
    service: LicenseService = Depends(get_license_service),
):
    """Generate a new unassigned or timed software license key for an organization."""
    return await service.generate_license(
        organization_id=payload.organization_id,
        tier=payload.tier,
        duration_days=payload.duration_days,
    )


@router.post("/licenses/activate", response_model=LicenseResponse, tags=["Licenses"])
async def activate_license(
    payload: LicenseActivateRequest,
    service: LicenseService = Depends(get_license_service),
):
    """Activate and bind a license key to a specific MikroTik router device."""
    return await service.activate_license(
        key=payload.license_key, router_id=payload.router_id
    )


@router.post("/licenses/validate", response_model=LicenseResponse, tags=["Licenses"])
async def validate_license(
    payload: LicenseValidateRequest,
    service: LicenseService = Depends(get_license_service),
):
    """Perform real-time secure verification of a router's license key status."""
    return await service.validate_license(
        key=payload.license_key,
        router_id=payload.router_id,
        organization_id=payload.organization_id,
    )


@router.post("/licenses/deactivate", response_model=LicenseResponse, tags=["Licenses"])
async def deactivate_license(
    key: str, service: LicenseService = Depends(get_license_service)
):
    """Deactivate a license key, unbinding it and disabling hardware capability."""
    return await service.deactivate_license(key)


@router.get(
    "/licenses/organization/{organization_id}",
    response_model=Sequence[LicenseResponse],
    tags=["Licenses"],
)
async def list_organization_licenses(
    organization_id: uuid.UUID,
    service: LicenseService = Depends(get_license_service),
):
    """List all software licenses purchased or issued to an organization."""
    return await service.list_organization_licenses(organization_id)

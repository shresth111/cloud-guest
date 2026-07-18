"""API Router for the Custom Domains domain."""

import uuid
from typing import Sequence
from fastapi import APIRouter, Depends, status

from .dependencies import get_custom_domain_service
from .schemas import CustomDomainCreate, CustomDomainResponse
from .service import CustomDomainService

router = APIRouter()


@router.post(
    "/domains",
    response_model=CustomDomainResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Domains"],
)
async def add_custom_domain(
    payload: CustomDomainCreate,
    service: CustomDomainService = Depends(get_custom_domain_service),
):
    """Add a new custom domain hostname map for an organization."""
    return await service.add_custom_domain(
        organization_id=payload.organization_id, domain_name=payload.domain_name
    )


@router.get(
    "/domains/organization/{organization_id}",
    response_model=Sequence[CustomDomainResponse],
    tags=["Domains"],
)
async def list_custom_domains(
    organization_id: uuid.UUID,
    service: CustomDomainService = Depends(get_custom_domain_service),
):
    """List all custom domains registered to an organization."""
    return await service.list_domains(organization_id)


@router.post(
    "/domains/{domain_id}/verify",
    response_model=CustomDomainResponse,
    tags=["Domains"],
)
async def verify_custom_domain(
    domain_id: uuid.UUID,
    service: CustomDomainService = Depends(get_custom_domain_service),
):
    """Trigger verification of TXT dns records to confirm domain ownership."""
    return await service.verify_domain_dns(domain_id)


@router.post(
    "/domains/{domain_id}/provision-ssl",
    response_model=CustomDomainResponse,
    tags=["Domains"],
)
async def provision_ssl_certificates(
    domain_id: uuid.UUID,
    service: CustomDomainService = Depends(get_custom_domain_service),
):
    """Complete SSL generation and bind active certs to verified custom domain."""
    return await service.complete_ssl_provisioning(domain_id)


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Domains"])
async def remove_custom_domain(
    domain_id: uuid.UUID,
    service: CustomDomainService = Depends(get_custom_domain_service),
):
    """Delete a custom domain map."""
    await service.remove_domain(domain_id)

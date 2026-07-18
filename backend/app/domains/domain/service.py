"""Service layer for the Custom Domains domain."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Sequence

from .constants import DNSValidationStatus, SSLStatus
from .exceptions import CustomDomainNotFoundError
from .models import CustomDomain
from .repository import CustomDomainRepositoryProtocol


class CustomDomainService:
    def __init__(self, repository: CustomDomainRepositoryProtocol) -> None:
        self.repository = repository

    def _generate_verification_token(self) -> str:
        """Generates a secure verification token to be set as a DNS TXT record."""
        return f"cloudguest-verification={secrets.token_hex(16)}"

    async def add_custom_domain(
        self, organization_id: uuid.UUID, domain_name: str
    ) -> CustomDomain:
        # Normalize domain
        domain_name = domain_name.lower().strip()
        
        existing = await self.repository.get_by_name(domain_name)
        if existing:
            return existing

        token = self._generate_verification_token()
        data = {
            "organization_id": organization_id,
            "domain_name": domain_name,
            "verification_token": token,
            "is_verified": False,
            "dns_validation_status": DNSValidationStatus.PENDING.value,
            "ssl_status": SSLStatus.PENDING.value,
        }

        return await self.repository.create_domain(data)

    async def verify_domain_dns(self, domain_id: uuid.UUID) -> CustomDomain:
        domain = await self.repository.get_by_id(domain_id)
        if not domain:
            raise CustomDomainNotFoundError(str(domain_id))

        # Mock query of DNS TXT records.
        # In production, we'd use dns.resolver to lookup TXT records for domain.domain_name
        # and match with domain.verification_token
        is_txt_verified = True  # Mocked success
        
        update_data = {}
        if is_txt_verified:
            update_data["is_verified"] = True
            update_data["dns_validation_status"] = DNSValidationStatus.VALID.value
            update_data["ssl_status"] = SSLStatus.ISSUING.value
        else:
            update_data["dns_validation_status"] = DNSValidationStatus.INVALID.value

        return await self.repository.update_domain(domain, update_data)

    async def complete_ssl_provisioning(self, domain_id: uuid.UUID) -> CustomDomain:
        domain = await self.repository.get_by_id(domain_id)
        if not domain:
            raise CustomDomainNotFoundError(str(domain_id))

        if not domain.is_verified:
            return domain

        # Mock certificate issuance.
        update_data = {
            "ssl_status": SSLStatus.ACTIVE.value,
            "ssl_configured_at": datetime.now(UTC),
        }
        return await self.repository.update_domain(domain, update_data)

    async def list_domains(self, organization_id: uuid.UUID) -> Sequence[CustomDomain]:
        return await self.repository.list_by_organization(organization_id)

    async def remove_domain(self, domain_id: uuid.UUID) -> None:
        domain = await self.repository.get_by_id(domain_id)
        if not domain:
            raise CustomDomainNotFoundError(str(domain_id))
        
        # Soft delete
        await self.repository.update_domain(domain, {"is_deleted": True})

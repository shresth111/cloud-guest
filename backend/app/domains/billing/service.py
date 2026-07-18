"""Service layer for the Billing domain."""

from __future__ import annotations

import uuid
from .exceptions import BillingProfileNotFoundError
from .models import BillingProfile
from .repository import BillingRepositoryProtocol


class BillingService:
    def __init__(self, repository: BillingRepositoryProtocol) -> None:
        self.repository = repository

    async def get_or_create_profile(self, organization_id: uuid.UUID) -> BillingProfile:
        profile = await self.repository.get_by_org_id(organization_id)
        if not profile:
            # Create a mock Customer ID (e.g., Stripe's 'cus_...')
            mock_customer_id = f"cus_{uuid.uuid4().hex[:14]}"
            profile_data = {
                "organization_id": organization_id,
                "customer_id": mock_customer_id,
                "billing_address": {},
            }
            profile = await self.repository.create_profile(profile_data)
        return profile

    async def update_profile(
        self, organization_id: uuid.UUID, data: dict
    ) -> BillingProfile:
        profile = await self.repository.get_by_org_id(organization_id)
        if not profile:
            profile = await self.get_or_create_profile(organization_id)
        
        return await self.repository.update_profile(profile, data)

    async def save_payment_method(
        self, organization_id: uuid.UUID, payment_method_id: str, brand: str, last4: str
    ) -> BillingProfile:
        profile = await self.get_or_create_profile(organization_id)
        update_data = {
            "payment_method_id": payment_method_id,
            "card_brand": brand,
            "card_last4": last4,
        }
        return await self.repository.update_profile(profile, update_data)

"""Business logic services for the Subscription domain."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Sequence

from .constants import PlanCode, SubscriptionStatus, BillingCycle
from .exceptions import (
    ActiveSubscriptionExistsError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
    InvalidSubscriptionStatusTransitionError,
)
from .models import Subscription, SubscriptionPlan, PlanChangeHistory
from .repository import SubscriptionRepositoryProtocol


class SubscriptionService:
    def __init__(self, repository: SubscriptionRepositoryProtocol) -> None:
        self.repository = repository

    async def get_plan(self, plan_id: uuid.UUID) -> SubscriptionPlan:
        plan = await self.repository.get_plan_by_id(plan_id)
        if not plan:
            raise PlanNotFoundError(str(plan_id))
        return plan

    async def get_plan_by_code(self, code: str) -> SubscriptionPlan:
        plan = await self.repository.get_plan_by_code(code)
        if not plan:
            raise PlanNotFoundError(code)
        return plan

    async def list_plans(self) -> Sequence[SubscriptionPlan]:
        return await self.repository.list_active_plans()

    async def create_plan(self, plan_data: dict) -> SubscriptionPlan:
        return await self.repository.create_plan(plan_data)

    async def get_organization_subscription(self, organization_id: uuid.UUID) -> Subscription:
        sub = await self.repository.get_subscription_by_org(organization_id)
        if not sub:
            raise SubscriptionNotFoundError(str(organization_id))
        return sub

    async def create_subscription(
        self,
        organization_id: uuid.UUID,
        plan_id: uuid.UUID,
        billing_cycle: str = "monthly",
        auto_renew: bool = True,
        trial_override_days: int | None = None
    ) -> Subscription:
        # Check if active subscription already exists
        existing = await self.repository.get_subscription_by_org(organization_id)
        if existing and existing.status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
            raise ActiveSubscriptionExistsError(str(organization_id))

        plan = await self.get_plan(plan_id)
        now = datetime.now(UTC)
        
        trial_days = trial_override_days if trial_override_days is not None else plan.trial_days
        
        trial_start = now if trial_days > 0 else None
        trial_end = now + timedelta(days=trial_days) if trial_days > 0 else None
        status = SubscriptionStatus.TRIALING if trial_days > 0 else SubscriptionStatus.ACTIVE

        # Calculate period end
        duration_days = 30 if billing_cycle == "monthly" else 365
        current_period_end = trial_end if trial_end else now + timedelta(days=duration_days)

        sub_data = {
            "organization_id": organization_id,
            "plan_id": plan_id,
            "status": status.value,
            "billing_cycle": billing_cycle,
            "current_period_start": now,
            "current_period_end": current_period_end,
            "trial_start": trial_start,
            "trial_end": trial_end,
            "auto_renew": auto_renew,
            "cancel_at_period_end": False
        }

        sub = await self.repository.create_subscription(sub_data)
        
        # Track history
        await self.repository.add_plan_change_history({
            "organization_id": organization_id,
            "old_plan_id": None,
            "new_plan_id": plan_id,
            "reason": "Initial subscription setup"
        })

        return sub

    async def change_plan(
        self,
        organization_id: uuid.UUID,
        new_plan_id: uuid.UUID,
        changed_by_user_id: uuid.UUID | None = None,
        reason: str | None = None
    ) -> Subscription:
        sub = await self.get_organization_subscription(organization_id)
        old_plan_id = sub.plan_id
        
        if old_plan_id == new_plan_id:
            return sub

        new_plan = await self.get_plan(new_plan_id)
        
        # In a real payment processor, we would prorate here
        # For now, update subscription details immediately
        update_data = {
            "plan_id": new_plan_id,
            "status": SubscriptionStatus.ACTIVE.value if sub.status != SubscriptionStatus.TRIALING else sub.status,
            "updated_at": datetime.now(UTC)
        }

        updated_sub = await self.repository.update_subscription(sub, update_data)

        # Log change history
        await self.repository.add_plan_change_history({
            "organization_id": organization_id,
            "old_plan_id": old_plan_id,
            "new_plan_id": new_plan_id,
            "changed_by_user_id": changed_by_user_id,
            "reason": reason or f"Upgraded/Downgraded to {new_plan.name}"
        })

        return updated_sub

    async def cancel_subscription(
        self,
        organization_id: uuid.UUID,
        immediately: bool = False
    ) -> Subscription:
        sub = await self.get_organization_subscription(organization_id)
        
        if immediately:
            update_data = {
                "status": SubscriptionStatus.CANCELED.value,
                "ended_at": datetime.now(UTC),
                "cancel_at_period_end": True,
                "canceled_at": datetime.now(UTC)
            }
        else:
            update_data = {
                "cancel_at_period_end": True,
                "canceled_at": datetime.now(UTC)
            }

        return await self.repository.update_subscription(sub, update_data)

    async def resume_subscription(self, organization_id: uuid.UUID) -> Subscription:
        sub = await self.get_organization_subscription(organization_id)
        if not sub.cancel_at_period_end:
            return sub

        update_data = {
            "cancel_at_period_end": False,
            "canceled_at": None
        }
        return await self.repository.update_subscription(sub, update_data)

    async def process_renewal(self, subscription_id: uuid.UUID) -> Subscription:
        sub = await self.repository.get_subscription_by_id(subscription_id)
        if not sub:
            raise SubscriptionNotFoundError(str(subscription_id))

        if sub.cancel_at_period_end:
            # End the subscription
            return await self.repository.update_subscription(sub, {
                "status": SubscriptionStatus.CANCELED.value,
                "ended_at": datetime.now(UTC)
            })

        now = datetime.now(UTC)
        duration_days = 30 if sub.billing_cycle == BillingCycle.MONTHLY else 365
        new_end = now + timedelta(days=duration_days)

        update_data = {
            "current_period_start": now,
            "current_period_end": new_end,
            "status": SubscriptionStatus.ACTIVE.value,
            "grace_period_end": None
        }

        return await self.repository.update_subscription(sub, update_data)

    async def handle_payment_failed(self, subscription_id: uuid.UUID) -> Subscription:
        sub = await self.repository.get_subscription_by_id(subscription_id)
        if not sub:
            raise SubscriptionNotFoundError(str(subscription_id))

        # Enter grace period (e.g., 3 days)
        now = datetime.now(UTC)
        grace_period_end = now + timedelta(days=3)

        update_data = {
            "status": SubscriptionStatus.PAST_DUE.value,
            "grace_period_end": grace_period_end
        }

        return await self.repository.update_subscription(sub, update_data)

    async def get_history(self, organization_id: uuid.UUID) -> Sequence[PlanChangeHistory]:
        return await self.repository.get_plan_change_history(organization_id)

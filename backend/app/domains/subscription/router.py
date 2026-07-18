"""API Router for the Subscription domain."""

import uuid
from typing import Sequence
from fastapi import APIRouter, Depends, HTTPException, status

from .dependencies import get_subscription_service
from .service import SubscriptionService
from .schemas import (
    SubscriptionPlanResponse,
    SubscriptionResponse,
    SubscriptionCreate,
    SubscriptionChangePlan,
    PlanChangeHistoryResponse,
)

router = APIRouter()


@router.get("/plans", response_model=Sequence[SubscriptionPlanResponse], tags=["Plans"])
async def list_plans(
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Retrieve all available active subscription plans."""
    return await service.list_plans()


@router.get("/plans/{plan_id}", response_model=SubscriptionPlanResponse, tags=["Plans"])
async def get_plan(
    plan_id: uuid.UUID,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Retrieve details of a specific subscription plan."""
    return await service.get_plan(plan_id)


@router.get("/subscriptions/{organization_id}", response_model=SubscriptionResponse, tags=["Subscriptions"])
async def get_organization_subscription(
    organization_id: uuid.UUID,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Retrieve the subscription active/trialling/historic for an organization."""
    return await service.get_organization_subscription(organization_id)


@router.post("/subscriptions", response_model=SubscriptionResponse, status_code=status.HTTP_201_CREATED, tags=["Subscriptions"])
async def create_subscription(
    payload: SubscriptionCreate,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Initialize a new subscription or free trial for an organization."""
    return await service.create_subscription(
        organization_id=payload.organization_id,
        plan_id=payload.plan_id,
        billing_cycle=payload.billing_cycle,
        auto_renew=payload.auto_renew,
    )


@router.post("/subscriptions/{organization_id}/change-plan", response_model=SubscriptionResponse, tags=["Subscriptions"])
async def change_plan(
    organization_id: uuid.UUID,
    payload: SubscriptionChangePlan,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Upgrade or downgrade an organization's plan."""
    return await service.change_plan(
        organization_id=organization_id,
        new_plan_id=payload.new_plan_id,
        reason=payload.reason,
    )


@router.post("/subscriptions/{organization_id}/cancel", response_model=SubscriptionResponse, tags=["Subscriptions"])
async def cancel_subscription(
    organization_id: uuid.UUID,
    immediately: bool = False,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Cancel an active subscription. Default is to cancel at period end."""
    return await service.cancel_subscription(organization_id, immediately=immediately)


@router.post("/subscriptions/{organization_id}/resume", response_model=SubscriptionResponse, tags=["Subscriptions"])
async def resume_subscription(
    organization_id: uuid.UUID,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Resume a pending subscription cancellation before period end."""
    return await service.resume_subscription(organization_id)


@router.get("/subscriptions/{organization_id}/history", response_model=Sequence[PlanChangeHistoryResponse], tags=["Subscriptions"])
async def get_subscription_history(
    organization_id: uuid.UUID,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get the audit log of all subscription updates for an organization."""
    return await service.get_history(organization_id)

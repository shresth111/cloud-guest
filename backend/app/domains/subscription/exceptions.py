"""Exceptions for the Subscription domain."""

from app.common.exceptions import CloudGuestError
from fastapi import status

class SubscriptionError(CloudGuestError):
    """Base exception for subscription domain errors."""

class PlanNotFoundError(SubscriptionError):
    def __init__(self, plan_id: str) -> None:
        super().__init__(
            f"Plan with id {plan_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class SubscriptionNotFoundError(SubscriptionError):
    def __init__(self, organization_id: str) -> None:
        super().__init__(
            f"Subscription for organization {organization_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

class ActiveSubscriptionExistsError(SubscriptionError):
    def __init__(self, organization_id: str) -> None:
        super().__init__(
            f"Organization {organization_id} already has an active subscription",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

class InvalidSubscriptionStatusTransitionError(SubscriptionError):
    def __init__(self, current: str, target: str) -> None:
        super().__init__(
            f"Cannot transition subscription from {current} to {target}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

class SubscriptionLimitExceededError(SubscriptionError):
    def __init__(self, resource: str, limit: int) -> None:
        super().__init__(
            f"Subscription limit exceeded for {resource}. Limit is {limit}",
            status_code=status.HTTP_403_FORBIDDEN,
        )

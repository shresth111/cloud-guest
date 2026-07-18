"""Validators for checking plan limits and subscription rules."""

from __future__ import annotations

import uuid
from typing import Any
from .exceptions import SubscriptionLimitExceededError


def validate_limit(resource_name: str, current_count: int, limit: int) -> None:
    """Check if the current resource usage exceeds the subscription plan limit.
    
    A limit of -1 represents 'unlimited' resource usage.
    """
    if limit == -1:
        return
    if current_count >= limit:
        raise SubscriptionLimitExceededError(resource=resource_name, limit=limit)

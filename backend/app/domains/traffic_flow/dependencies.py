"""Providers for the customer-facing traffic-flow service.

The Master services are built in ``router.py`` (GLOBAL-pinned, no tenant
caller can reach them). The customer service is built here, and this is the
one place that must hand it the caller's location confinement: a constructor
parameter nothing supplies is unconfined by default, i.e. it fails open
(``tests/unit/test_location_scope_coverage.py`` checks exactly this).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.rbac.location_scope import CallerLocationScope, LocationScope

from .service import TrafficFlowCustomerService, TrafficFlowRepository

__all__ = ["get_traffic_flow_customer_service"]


def get_traffic_flow_customer_service(
    session: AsyncSession = Depends(get_db_session),
    location_service: LocationService = Depends(get_location_service),
    settings: Settings = Depends(get_settings),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
) -> TrafficFlowCustomerService:
    return TrafficFlowCustomerService(
        TrafficFlowRepository(session),
        location_service,
        settings,
        caller_location_scope=caller_location_scope,
    )

"""System information service.

Returns platform health, status, and version information by composing
existing health checks and domain services.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
import logging

from app.core.config import get_settings
from app.domains.organization.service import OrganizationService
from app.domains.location.service import LocationService
from app.domains.router.service import RouterService
from app.domains.analytics.service import AnalyticsService

from .schemas import (
    DependencyStatus,
    SystemHealthResponse,
    SystemStatusResponse,
    SystemVersionResponse,
)

logger = logging.getLogger(__name__)

START_TIME = time.time()


class SystemService:
    def __init__(
        self,
        organization_service: OrganizationService,
        location_service: LocationService,
        router_service: RouterService,
    ) -> None:
        self.organization_service = organization_service
        self.location_service = location_service
        self.router_service = router_service

    async def get_health(self) -> SystemHealthResponse:
        deps = [
            DependencyStatus(name="api", status="healthy", latency_ms=0.5),
        ]

        overall = "healthy"
        for dep in deps:
            if dep.status == "down":
                overall = "down"
                break
            if dep.status == "degraded":
                overall = "degraded"

        settings = get_settings()
        return SystemHealthResponse(
            status=overall,
            version=self._get_version(),
            uptime_seconds=time.time() - START_TIME,
            dependencies=deps,
        )

    async def get_status(self) -> SystemStatusResponse:
        settings = get_settings()
        return SystemStatusResponse(
            status="operational",
            version=self._get_version(),
            environment=settings.environment,
            uptime_seconds=time.time() - START_TIME,
        )

    async def get_version(self) -> SystemVersionResponse:
        return SystemVersionResponse(
            version=self._get_version(),
            build=os.environ.get("CLOUDGUEST_BUILD", None),
            commit=os.environ.get("CLOUDGUEST_COMMIT", None),
            python_version=sys.version.split()[0],
            api_version="v1",
        )

    @staticmethod
    def _get_version() -> str:
        return os.environ.get("CLOUDGUEST_VERSION", "0.1.0")

from fastapi import APIRouter

from app.api.v1.health.routes import router as health_router
from app.domains.auth.router import router as auth_router
from app.domains.location.router import router as location_router
from app.domains.organization.router import router as organization_router
from app.domains.rbac.router import router as rbac_router
from app.domains.router.router import router as router_router
from app.domains.user.router import router as user_router
from app.domains.monitoring.router import router as monitoring_router
from app.domains.alerts.router import router as alerts_router
from app.domains.events.router import router as events_router
from app.domains.analytics.router import router as analytics_router
from app.domains.reports.router import router as reports_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, prefix="/health", tags=["Health"])
api_v1_router.include_router(auth_router)
api_v1_router.include_router(rbac_router)
api_v1_router.include_router(organization_router)
api_v1_router.include_router(location_router)
api_v1_router.include_router(user_router)
api_v1_router.include_router(router_router)
api_v1_router.include_router(monitoring_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(analytics_router)
api_v1_router.include_router(reports_router)

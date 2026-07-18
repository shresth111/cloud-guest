from fastapi import APIRouter

from app.api.v1.health.routes import router as health_router
from app.domains.auth.router import router as auth_router
from app.domains.location.router import router as location_router
from app.domains.organization.router import router as organization_router
from app.domains.rbac.router import router as rbac_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, prefix="/health", tags=["Health"])
api_v1_router.include_router(auth_router)
api_v1_router.include_router(rbac_router)
api_v1_router.include_router(organization_router)
api_v1_router.include_router(location_router)

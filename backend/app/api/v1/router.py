from fastapi import APIRouter

from app.api.v1.health.routes import router as health_router
from app.domains.analytics.router import router as analytics_router
from app.domains.auth.router import router as auth_router
from app.domains.billing.router import router as billing_router
from app.domains.captive_portal.router import router as captive_portal_router
from app.domains.dhcp.router import router as dhcp_router
from app.domains.guest.router import admin_router as guest_admin_router
from app.domains.guest.router import analytics_router as guest_analytics_router
from app.domains.guest.router import guest_router
from app.domains.guest.router import nas_cross_reference_router as guest_nas_xref_router
from app.domains.guest.router import nas_router as guest_nas_router
from app.domains.guest.router import radius_router as guest_radius_router
from app.domains.guest_access.router import router as guest_access_router
from app.domains.guest_teams.router import admin_router as guest_teams_admin_router
from app.domains.guest_teams.router import guest_router as guest_teams_guest_router
from app.domains.isp.router import router as isp_router
from app.domains.isp_routing.router import router as isp_routing_router
from app.domains.location.router import router as location_router
from app.domains.mac_authorization.router import router as mac_authorization_router
from app.domains.monitoring.router import router as monitoring_router
from app.domains.organization.router import router as organization_router
from app.domains.otp.router import router as otp_router
from app.domains.policy.router import router as policy_router
from app.domains.port_forwarding.router import router as port_forwarding_router
from app.domains.provisioning_engine.router import router as provisioning_engine_router
from app.domains.queue_management.router import router as queue_management_router
from app.domains.rbac.router import router as rbac_router
from app.domains.router.router import router as router_router
from app.domains.router_agent.router import router as router_agent_router
from app.domains.router_provisioning.router import router as router_provisioning_router
from app.domains.user.router import router as user_router
from app.domains.vlan.router import router as vlan_router
from app.domains.voucher.router import router as voucher_router
from app.domains.wireguard.router import router as wireguard_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, prefix="/health", tags=["Health"])
api_v1_router.include_router(auth_router)
api_v1_router.include_router(rbac_router)
api_v1_router.include_router(organization_router)
api_v1_router.include_router(location_router)
api_v1_router.include_router(user_router)
api_v1_router.include_router(router_router)
api_v1_router.include_router(router_provisioning_router)
api_v1_router.include_router(router_agent_router)
api_v1_router.include_router(wireguard_router)
api_v1_router.include_router(otp_router)
api_v1_router.include_router(voucher_router)
api_v1_router.include_router(captive_portal_router)
api_v1_router.include_router(guest_router)
api_v1_router.include_router(guest_admin_router)
api_v1_router.include_router(guest_radius_router)
api_v1_router.include_router(guest_nas_router)
api_v1_router.include_router(guest_nas_xref_router)
api_v1_router.include_router(guest_analytics_router)
api_v1_router.include_router(guest_access_router)
api_v1_router.include_router(guest_teams_guest_router)
api_v1_router.include_router(guest_teams_admin_router)
api_v1_router.include_router(monitoring_router)
api_v1_router.include_router(analytics_router)
api_v1_router.include_router(billing_router)
api_v1_router.include_router(policy_router)
api_v1_router.include_router(provisioning_engine_router)
api_v1_router.include_router(queue_management_router)
api_v1_router.include_router(isp_router)
api_v1_router.include_router(isp_routing_router)
api_v1_router.include_router(vlan_router)
api_v1_router.include_router(dhcp_router)
api_v1_router.include_router(port_forwarding_router)
api_v1_router.include_router(mac_authorization_router)

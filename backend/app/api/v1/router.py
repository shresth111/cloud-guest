from fastapi import APIRouter, Depends

from app.domains.billing.dependencies import RequireActiveLicenseForWrites

from app.api.v1.health.routes import router as health_router
from app.domains.admin_logs.router import router as admin_logs_router
from app.domains.agent_permissions.router import router as agent_permissions_router
from app.domains.analytics.router import router as analytics_router
from app.domains.api_keys.router import router as api_keys_router
from app.domains.assistant.router import router as assistant_router
from app.domains.audit.router import router as audit_router
from app.domains.auth.router import router as auth_router
from app.domains.billing.router import router as billing_router
from app.domains.branding.router import router as branding_router
from app.domains.campaigns.router import guest_router as campaigns_guest_router
from app.domains.campaigns.router import router as campaigns_router
from app.domains.captive_portal.router import router as captive_portal_router
from app.domains.channel_partner.router import router as channel_partner_router
from app.domains.connected_devices.router import router as connected_devices_router
from app.domains.content_filtering.router import router as content_filtering_router
from app.domains.controller_logs.router import router as controller_logs_router
from app.domains.customer_provisioning.router import (
    router as customer_provisioning_router,
)
from app.domains.dashboard.router import router as dashboard_router
from app.domains.demo_booking.router import router as demo_booking_router
from app.domains.demo_request.router import router as demo_request_router
from app.domains.device_sync.router import router as device_sync_router
from app.domains.dhcp.router import router as dhcp_router
from app.domains.dns.router import router as dns_router
from app.domains.feature_entitlement.router import router as feature_entitlement_router
from app.domains.firewall.router import router as firewall_router
from app.domains.guest.router import admin_router as guest_admin_router
from app.domains.guest.router import analytics_router as guest_analytics_router
from app.domains.guest.router import guest_router
from app.domains.guest.router import nas_cross_reference_router as guest_nas_xref_router
from app.domains.guest.router import nas_platform_router as guest_nas_platform_router
from app.domains.guest.router import nas_router as guest_nas_router
from app.domains.guest.router import radius_router as guest_radius_router
from app.domains.guest_access.router import router as guest_access_router
from app.domains.guest_teams.router import admin_router as guest_teams_admin_router
from app.domains.guest_teams.router import guest_router as guest_teams_guest_router
from app.domains.hotspot.router import router as hotspot_router
from app.domains.hub_reconciliation.router import router as hub_reconciliation_router
from app.domains.isp.router import router as isp_router
from app.domains.isp_routing.router import router as isp_routing_router
from app.domains.live_sessions.router import router as live_sessions_router
from app.domains.location.router import router as location_router
from app.domains.mac_authorization.router import router as mac_authorization_router
from app.domains.monitored_hardware.router import router as monitored_hardware_router
from app.domains.monitoring.router import router as monitoring_router
from app.domains.network_config.router import router as network_config_router
from app.domains.network_device.router import router as network_device_router
from app.domains.network_diagnostics.router import router as network_diagnostics_router
from app.domains.notification.router import router as notification_router
from app.domains.organization.router import router as organization_router
from app.domains.otp.router import router as otp_router
from app.domains.policy.router import router as policy_router
from app.domains.port_forwarding.router import router as port_forwarding_router
from app.domains.provisioning_engine.router import router as provisioning_engine_router
from app.domains.qos.router import router as qos_router
from app.domains.queue_management.router import router as queue_management_router
from app.domains.quotation.router import router as quotation_router
from app.domains.rbac.router import router as rbac_router
from app.domains.readiness.router import router as readiness_router
from app.domains.router.router import router as router_router
from app.domains.router_agent.router import router as router_agent_router
from app.domains.router_provisioning.router import router as router_provisioning_router
from app.domains.support_tickets.router import router as support_tickets_router
from app.domains.system.router import router as system_router
from app.domains.system_settings.router import router as system_settings_router
from app.domains.user.router import router as user_router
from app.domains.vlan.router import router as vlan_router
from app.domains.voucher.router import router as voucher_router
from app.domains.wireguard.router import router as wireguard_router
from app.domains.workspace.router import router as workspace_router


# ---------------------------------------------------------------------------
# Licence gating
# ---------------------------------------------------------------------------
#
# `RequireActiveLicenseForWrites` 402s a state-changing request from an
# organization whose licence is expired, suspended, or absent entirely. It is
# applied here, at the include, rather than decorated onto endpoints one at a
# time: which router families are gated then reads as one list instead of a
# hundred separate decisions, and a new endpoint added to an already-gated
# router is covered by construction rather than by remembering.
#
# Reads are never gated. A customer whose plan lapsed must still sign in, see
# their venues, read their guest list, and reach billing to pay -- locking
# them out of the evidence of what they are paying for is the wrong lever.
#
# NOT gated, deliberately:
#
# * Every guest-facing path -- `guest_router`, `captive_portal`'s own
#   unauthenticated resolve, `campaigns_guest_router`,
#   `guest_teams_guest_router`, `otp_router`, and the RADIUS/NAS routers.
#   Cutting a venue's guest WiFi over a billing state would punish the guests
#   standing in its lobby for the owner's lapsed card, and turn a revenue
#   problem into an outage. This is the single most important line here.
# * `voucher_router` -- it carries two *unauthenticated* POSTs,
#   `/vouchers/validate` and `/vouchers/redeem`, which are how a guest with a
#   front-desk code gets online. They sit on the same router as the admin
#   batch CRUD, so the router cannot be gated without gating them, and a
#   guest holding a valid voucher must not be turned away because the venue's
#   card expired. Gating the admin half needs per-endpoint dependencies;
#   left for a follow-up rather than risking the guest half here.
# * `billing_router` -- gating payment behind "you must have paid" makes a
#   lapsed account unrecoverable. Same reasoning the licence-lifecycle
#   endpoints already document for themselves.
# * `auth_router`, `user_router`, `rbac_router`, `organization_router`,
#   `location_router` -- account and access management. An owner must be able
#   to log in, fix a user, and reach the rest of the product.
# * `support_tickets_router`, `demo_request_router`, `demo_booking_router`,
#   `quotation_router` -- how a lapsed customer talks to us. Gating these
#   would silence the exact conversation that gets them paying again.
# * `router_*`, `provisioning_engine`, `wireguard`, `hub_reconciliation`,
#   `device_sync`, `monitoring`, `readiness`, `system*`, `admin_logs`,
#   `controller_logs`, `audit` -- platform-operator and device-fleet surfaces,
#   several of which run as the platform with no organization context at all.
_LICENCE_GATED_WRITES = [Depends(RequireActiveLicenseForWrites())]

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
api_v1_router.include_router(hub_reconciliation_router)
api_v1_router.include_router(otp_router)
api_v1_router.include_router(voucher_router)
api_v1_router.include_router(captive_portal_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(guest_router)
api_v1_router.include_router(guest_admin_router)
api_v1_router.include_router(guest_radius_router)
api_v1_router.include_router(guest_nas_router)
api_v1_router.include_router(guest_nas_xref_router)
api_v1_router.include_router(guest_nas_platform_router)
api_v1_router.include_router(guest_analytics_router)
api_v1_router.include_router(guest_access_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(guest_teams_guest_router)
api_v1_router.include_router(guest_teams_admin_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(monitoring_router)
api_v1_router.include_router(analytics_router)
api_v1_router.include_router(billing_router)
api_v1_router.include_router(policy_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(provisioning_engine_router)
api_v1_router.include_router(queue_management_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(isp_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(isp_routing_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(vlan_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(dhcp_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(dns_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(firewall_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(port_forwarding_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(mac_authorization_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(connected_devices_router)
api_v1_router.include_router(device_sync_router)
api_v1_router.include_router(controller_logs_router)
api_v1_router.include_router(admin_logs_router)
api_v1_router.include_router(network_config_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(hotspot_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(qos_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(network_diagnostics_router)
api_v1_router.include_router(network_device_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(monitored_hardware_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(content_filtering_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(campaigns_guest_router)
api_v1_router.include_router(campaigns_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(notification_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(api_keys_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(workspace_router)
api_v1_router.include_router(feature_entitlement_router)
api_v1_router.include_router(agent_permissions_router)
api_v1_router.include_router(live_sessions_router)
api_v1_router.include_router(customer_provisioning_router)
api_v1_router.include_router(system_router)
api_v1_router.include_router(system_settings_router)
api_v1_router.include_router(branding_router, dependencies=_LICENCE_GATED_WRITES)
api_v1_router.include_router(support_tickets_router)
api_v1_router.include_router(demo_request_router)
api_v1_router.include_router(demo_booking_router)
api_v1_router.include_router(quotation_router)
api_v1_router.include_router(assistant_router)
api_v1_router.include_router(readiness_router)
api_v1_router.include_router(channel_partner_router)

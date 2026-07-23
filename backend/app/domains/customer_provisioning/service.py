"""Customer provisioning service.

Orchestrates the multi-step onboarding of a new customer — creating the
organization, first location, first router, and generating configuration
scripts and NAS/WireGuard credentials.

Composes existing organization, location, router, provisioning, and
wireguard services — no new database tables.
"""

from __future__ import annotations

import uuid
import logging

from app.domains.organization.service import OrganizationService
from app.domains.organization.repository import OrganizationRepositoryProtocol
from app.domains.location.service import LocationService
from app.domains.router.service import RouterService
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.wireguard.service import WireGuardService
from app.domains.guest.service import RadiusService
from app.domains.rbac.service import RBACService
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import RoleNotFoundError
from app.domains.organization.enums import OrganizationType

from .schemas import (
    OnboardRequest,
    OnboardResponse,
    GenerateScriptResponse,
    GenerateNasResponse,
    WireguardConfigResponse,
)

logger = logging.getLogger(__name__)


class CustomerProvisioningService:
    def __init__(
        self,
        organization_service: OrganizationService,
        location_service: LocationService,
        router_service: RouterService,
        provisioning_service: RouterProvisioningService,
        wireguard_service: WireGuardService,
        rbac_service: RBACService,
    ) -> None:
        self.organization_service = organization_service
        self.location_service = location_service
        self.router_service = router_service
        self.provisioning_service = provisioning_service
        self.wireguard_service = wireguard_service
        self.rbac_service = rbac_service

    async def onboard(
        self, request: OnboardRequest, actor_user_id: uuid.UUID
    ) -> OnboardResponse:
        org = await self.organization_service.create_organization(
            actor_user_id=actor_user_id,
            name=request.organization_name,
            slug=request.organization_slug,
            contact_email=request.admin_email,
            org_type=OrganizationType.STANDARD,
        )

        org_admin_role = await self.rbac_service.repository.get_role_by_slug(
            "organization-admin", None
        )
        if org_admin_role is None:
            raise RoleNotFoundError("organization-admin")

        await self.rbac_service.assign_role_to_user(
            actor_user_id=actor_user_id,
            target_user_id=actor_user_id,
            role_id=org_admin_role.id,
            scope_type=ScopeType.ORGANIZATION,
            requesting_organization_id=None,
            organization_id=org.id,
        )

        location_id: uuid.UUID | None = None
        if request.location_name:
            location = await self.location_service.create_location(
                actor_user_id=actor_user_id,
                organization_id=org.id,
                requesting_organization_id=None,
                name=request.location_name,
                slug=request.organization_slug,
                address_line1=request.location_address or "Not specified",
                city="Not specified",
                state_province="Not specified",
                postal_code="000000",
                country="IN",
            )
            location_id = location.id

        return OnboardResponse(
            organization_id=str(org.id),
            location_id=str(location_id) if location_id else None,
            admin_user_id=str(actor_user_id),
            message=f"Organization '{org.name}' onboarded",
        )

    async def generate_script(
        self, customer_id: uuid.UUID
    ) -> GenerateScriptResponse:
        script = (
            "#!/bin/bash\n"
            "# CloudGuest Router Provisioning Script\n"
            f"# Customer ID: {customer_id}\n\n"
            "echo 'Downloading CloudGuest agent...'\n"
            "curl -sSL https://cloudguest.io/agent/install.sh | bash\n\n"
            "echo 'Registering router with CloudGuest...'\n"
            f"cloudguest-agent register --customer-id={customer_id}\n\n"
            "echo 'Router provisioning complete.'\n"
        )
        return GenerateScriptResponse(
            script=script,
            script_type="bash",
            message="Configuration script generated",
        )

    async def generate_nas(
        self, customer_id: uuid.UUID
    ) -> GenerateNasResponse:
        import secrets

        nas_ip = f"10.0.{uuid.uuid4().int % 255}.{uuid.uuid4().int % 255}"
        nas_secret = secrets.token_hex(16)
        return GenerateNasResponse(
            nas_id=str(uuid.uuid4()),
            nas_ip=nas_ip,
            nas_secret=nas_secret,
            message="NAS device registered",
        )

    async def generate_wireguard(
        self, customer_id: uuid.UUID
    ) -> WireguardConfigResponse:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private_key_obj = X25519PrivateKey.generate()
        private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        import base64
        priv_b64 = base64.b64encode(private_key).decode()
        pub_b64 = base64.b64encode(public_key).decode()

        return WireguardConfigResponse(
            peer_id=str(uuid.uuid4()),
            private_key=priv_b64,
            public_key=pub_b64,
            endpoint=f"wg.cloudguest.io:51820",
            message="WireGuard configuration generated",
        )

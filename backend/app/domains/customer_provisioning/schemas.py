from __future__ import annotations

from pydantic import BaseModel


class OnboardRequest(BaseModel):
    organization_name: str
    organization_slug: str
    location_name: str | None = None
    location_address: str | None = None
    router_name: str | None = None
    router_model: str | None = None
    admin_email: str
    admin_password: str | None = None
    plan_slug: str = "starter"


class OnboardResponse(BaseModel):
    organization_id: str
    location_id: str | None = None
    router_id: str | None = None
    admin_user_id: str
    message: str = "Organization onboarded successfully"


class GenerateScriptRequest(BaseModel):
    router_model: str | None = None
    config_variables: dict[str, str] | None = None


class GenerateScriptResponse(BaseModel):
    script: str
    script_type: str = "bash"
    message: str = "Configuration script generated"


class GenerateNasResponse(BaseModel):
    nas_id: str
    nas_ip: str
    nas_secret: str
    nas_type: str = "MikroTik"
    message: str = "NAS device registered"


class WireguardConfigResponse(BaseModel):
    peer_id: str
    private_key: str
    public_key: str
    endpoint: str
    allowed_ips: str = "0.0.0.0/0"
    dns: str = "8.8.8.8"
    message: str = "WireGuard configuration generated"

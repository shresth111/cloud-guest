from __future__ import annotations

from pydantic import BaseModel


class OnboardRequest(BaseModel):
    """Input for the one real operation this domain performs.

    Deliberately narrow: it carries only the fields ``onboard`` actually
    acts on. Fields that used to sit here (``router_name``,
    ``router_model``, ``admin_password``, ``plan_slug``) were never read
    by the service -- a caller could ask for a router, or set an admin
    password, and receive a 201 with none of it having happened. Router
    provisioning has its own real domain (``router_provisioning``);
    plans/licensing have theirs (``billing``).
    """

    organization_name: str
    organization_slug: str
    location_name: str | None = None
    location_address: str | None = None
    admin_email: str


class OnboardResponse(BaseModel):
    organization_id: str
    location_id: str | None = None
    admin_user_id: str
    message: str = "Organization onboarded successfully"

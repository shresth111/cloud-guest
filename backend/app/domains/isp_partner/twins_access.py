"""B2 (Access & Policy): Guest Groups venue twins.

Access Rules, Guest Allow-list, Trusted Devices and Open Hours were twinned in
``twins_venue`` (cherry-picked from integ); this adds Guest Groups
(``/guest-teams`` admin router, on ``_PAID_WRITES``).

ADDENDUM_04 flags the guest-teams admin LIST as an open location-filter
defect (PR #309, not on main): with no ``location_id`` it lists every team of
the org. The twin therefore always injects the workspace's location from
``X-Isp-Location-Id`` -- it is never a request parameter, so it can never be
left empty. Create forces the body's ``organization_id``/``location_id`` the
same way. By-id routes rely on the service's org check (a team of another
customer is a 404); a team of another location of the SAME customer stays
reachable by id, which is the same customer's data.
"""

from __future__ import annotations

import inspect
import uuid

from app.domains.guest_teams import router as guest_teams_routes
from app.domains.guest_teams.dependencies import get_guest_team_service
from app.domains.guest_teams.schemas import (
    GuestTeamCreateRequest,
    GuestTeamMemberRemoveRequest,
    GuestTeamRevokeRequest,
)

from .constants import (
    ISP_ACCESS_CREATE,
    ISP_ACCESS_EXECUTE,
    ISP_ACCESS_READ,
)
from .twin_body import BodyId
from .twins import Param, TwinSpec

__all__ = ["ACCESS_TWINS"]

_TeamId = Param("team_id", "path", uuid.UUID)
_deps = {"service": get_guest_team_service}


def _body(model) -> Param:
    return Param("payload", "body", model, inspect.Parameter.empty)


ACCESS_TWINS: tuple[TwinSpec, ...] = (
    TwinSpec(
        method="GET",
        path="/venue/guest-teams",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.list_guest_teams,
        target="header_location",
        params=(Param("page", "query", int, 1), Param("page_size", "query", int, 25)),
        deps=_deps,
        inject={
            "requesting_organization_id": ("org",),
            # ALWAYS the workspace location (open defect PR #309: an empty
            # location_id lists every team of the org).
            "location_id": ("location",),
            "status_filter": ("const", None),
        },
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-teams",
        permission_key=ISP_ACCESS_CREATE,
        handler=guest_teams_routes.create_guest_team,
        target="header_location",
        params=(_body(GuestTeamCreateRequest),),
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
        status_code=201,
    ),
    TwinSpec(
        method="GET",
        path="/venue/guest-teams/{team_id}",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.get_guest_team,
        target="header_location",
        params=(_TeamId,),
        deps=_deps,
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/guest-teams/{team_id}/members",
        permission_key=ISP_ACCESS_READ,
        handler=guest_teams_routes.list_guest_team_members,
        target="header_location",
        params=(_TeamId,),
        deps=_deps,
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="DELETE",
        path="/venue/guest-teams/{team_id}/members/{guest_id}",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_teams_routes.remove_guest_team_member,
        target="header_location",
        params=(
            _TeamId,
            Param("guest_id", "path", uuid.UUID),
            _body(GuestTeamMemberRemoveRequest),
        ),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/guest-teams/{team_id}/revoke",
        permission_key=ISP_ACCESS_EXECUTE,
        handler=guest_teams_routes.revoke_guest_team,
        target="header_location",
        params=(_TeamId, _body(GuestTeamRevokeRequest)),
        deps=_deps,
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
    ),
)

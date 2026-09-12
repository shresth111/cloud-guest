"""FastAPI dependencies for the Network Integration domain.

One repository provider and one service provider, wired from the same
shared singletons every other domain already uses -- never a second,
parallel construction path.

## Why ``OptionalCallerLocationScope`` and not ``CallerLocationScope``

``CallerLocationScope`` depends on ``CurrentUser``, and FastAPI resolves
every declared dependency *before* the endpoint body runs. This domain's
service backs both the RBAC-gated customer/platform routes **and** the
public ``POST /portal/authorize``, so wiring the strict variant here would
force authentication on the guest portal -- turning a guest's WiFi join
into a 401.

That is not hypothetical. ``tests/unit/test_location_scope_coverage.py``'s
own docstring records the incident: converting ``queue_management`` and
``mac_authorization`` with the strict dependency silently added
authentication to fifteen routes, including every guest login method and
``POST /radius/authorize`` -- "it would have 401'd, at every venue at
once".

The anonymous-tolerant variant resolves to ``None`` (unconfined) only when
*no credential is presented at all*. A credential that is present but
invalid still propagates its failure, so a caller cannot shed their
confinement by corrupting their own token.

## Why unconfined-when-anonymous is safe here

Because it is never the whole of a route's defence, which is the property
that test enforces rather than assumes:

* every customer/platform route carries ``RequirePermission``, so an
  anonymous caller dead-ends at 401 long before the service is consulted;
* the one anonymous route, ``POST /portal/authorize``, does not use the
  location confinement at all. It proves its own claim from scratch -- an
  ``ACTIVE`` ``GuestSession`` whose organization *and* location match the
  body -- and resolves the integration from the *session's* venue rather
  than the caller's. A location confinement would be meaningless there: a
  guest holds no roles, so there is nothing to derive one from.

``POST /api/v1/network-integrations/portal/authorize`` is listed in that
test's ``_GUEST_FACING_UNCONFINED`` allowlist with that reasoning, in
writing, rather than being skipped.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_service
from app.domains.guest.repository import GuestRepository
from app.domains.guest.service import GuestService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.location_scope import (
    LocationScope,
    OptionalCallerLocationScope,
)
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import (
    NetworkIntegrationRepository,
    NetworkIntegrationRepositoryProtocol,
)
from .service import (
    FleetDeviceProvisionerProtocol,
    GuestSessionLookupProtocol,
    GuestSessionTerminatorProtocol,
    NetworkIntegrationService,
)

__all__ = [
    "get_fleet_device_provisioner",
    "get_guest_session_lookup",
    "get_guest_session_terminator",
    "get_network_integration_repository",
    "get_network_integration_service",
]


def get_network_integration_repository(
    db: AsyncSession = Depends(get_db_session),
) -> NetworkIntegrationRepositoryProtocol:
    return NetworkIntegrationRepository(db)


def get_guest_session_lookup(
    db: AsyncSession = Depends(get_db_session),
) -> GuestSessionLookupProtocol:
    """The real ``GuestRepository``, satisfying this domain's two-line
    Protocol.

    The *repository*, not ``GuestService``: see
    ``service.GuestSessionLookupProtocol``'s own docstring for why. A
    ``GuestRepository`` is constructed from an ``AsyncSession`` and nothing
    else, so this costs no service graph and pulls no other domain's
    dependencies into this one's.
    """
    return GuestRepository(db)


def get_guest_session_terminator(
    guest_service: GuestService = Depends(get_guest_service),
) -> GuestSessionTerminatorProtocol:
    """The real ``GuestService``, satisfying this domain's one-method
    Protocol for the staff disconnect.

    The *service*, not the repository -- the opposite choice from
    ``get_guest_session_lookup`` above, and deliberately so. Reading a
    session is a query; ending one is a state transition that must be
    validated against the status graph, stamped, audited, and accompanied
    by the live RFC 5176 disconnect the venue's other enforcement path
    depends on. A repository write would do the first of those and skip
    the rest.

    It costs a service graph, which is exactly why it is a separate
    dependency rather than being folded into the lookup: the anonymous
    ``POST /portal/authorize`` resolves this service too, and there is no
    reason for a guest joining the WiFi to construct ``GuestService``.
    FastAPI resolves declared dependencies eagerly, so this one is
    resolved on every route in the domain -- the cost is construction,
    not I/O, and the alternative (resolving it inside the endpoint) would
    put a second, parallel construction path in the codebase, which this
    module's docstring exists to forbid.

    Direction check: this domain reaches into ``app.domains.guest``;
    nothing in ``app.domains.guest`` reaches back. Keep it that way, or
    the portal authorize endpoint stops being able to fail independently
    of guest login.
    """
    return guest_service


def get_fleet_device_provisioner(
    router_service: RouterService = Depends(get_router_service),
) -> FleetDeviceProvisionerProtocol:
    """The real ``RouterService``, satisfying this domain's one-method
    Protocol for the Master onboarding path.

    Composed through the router domain's own dependency rather than
    constructed here, so the fleet rows this path writes go through exactly
    the same service -- and the same location, duplicate-serial and
    duplicate-MAC checks -- as a router added from the Master device screen.
    It resolves from ``get_db_session``, which is request-scoped, so the
    integration write and the fleet write share one session and one
    transaction. That shared transaction is what makes the pair atomic; see
    ``service.create_integration_with_fleet_device``.
    """
    return router_service


def get_network_integration_service(
    repository: NetworkIntegrationRepositoryProtocol = Depends(
        get_network_integration_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    guest_session_lookup: GuestSessionLookupProtocol = Depends(
        get_guest_session_lookup
    ),
    guest_session_terminator: GuestSessionTerminatorProtocol = Depends(
        get_guest_session_terminator
    ),
    # The same real app.database.redis.redis_client singleton every other
    # Redis-backed limiter in this codebase reuses (OtpRateLimiter,
    # VoucherRedemptionRateLimiter, RateLimitMiddleware) -- not a new
    # client. Backs the portal authorize per-session limiter.
    redis: Redis = Depends(get_redis_client),
    caller_location_scope: LocationScope = Depends(OptionalCallerLocationScope),
    fleet_device_provisioner: FleetDeviceProvisionerProtocol = Depends(
        get_fleet_device_provisioner
    ),
) -> NetworkIntegrationService:
    return NetworkIntegrationService(
        repository,
        audit_writer=audit_repository,
        guest_session_lookup=guest_session_lookup,
        guest_session_terminator=guest_session_terminator,
        fleet_device_provisioner=fleet_device_provisioner,
        redis=redis,
        caller_location_scope=caller_location_scope,
    )

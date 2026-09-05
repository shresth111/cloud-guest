"""The set of locations a caller is confined to, if they are confined at all.

## The gap this closes

Most resources in this product are reached by their own id -- ``DELETE
/firewall-rules/{rule_id}``, ``PUT /dhcp-pools/{pool_id}``, ``DELETE
/vlans/{vlan_id}``. A ``rule_id`` says nothing about which tenant or which site
it belongs to until the row is loaded, and the row loads *after*
``RequirePermission`` has already run. So RBAC structurally cannot pin these
the way ``dependencies._current_scope_context`` pins a route that names a
router or a location in its URL.

The services behind them close the tenant half and stop there:
``FirewallService.get_rule`` compares ``rule.organization_id`` against
``requesting_organization_id`` and nothing else. Five domains sampled
(``firewall``, ``content_filtering``, ``dhcp``, ``qos``, ``port_forwarding``)
carry roughly a hundred organization comparisons between them and **zero**
location comparisons.

The consequence, concretely: a front-desk or engineering account scoped to
site A, holding ``firewall.delete``, sends its own ``X-Location-Id``; the
permission check is satisfied by its own LOCATION grant; the service compares
only the organization; and a firewall rule at site B in the same organization
is deleted.

## Why the constraint comes from the grant, not from the header

The obvious implementation -- pass ``Depends(CurrentLocation)`` into services
and compare it -- would be wrong, and wrong in the dangerous direction: it
would lock legitimate users out of their own data.

``X-Location-Id`` is UI context. An organization administrator browsing site A
sends it while still being entitled to every site; comparing the entity's
location against that header would refuse them their own organization's
resources the moment they navigated. A header is what the caller *is looking
at*; it is not a statement about what they are *entitled to*.

So the constraint is derived from the caller's actual role assignments:

* holds any active GLOBAL-scoped role  -> ``None`` (unconstrained)
* holds any active ORGANIZATION-scoped role -> ``None`` (unconstrained)
* otherwise -> the set of ``location_id``s their LOCATION- and ROUTER-scoped
  assignments name

``None`` means "do not filter", so platform operators and organization
administrators are unaffected by construction -- they cannot be locked out by
this, because the only branch that constrains anyone requires the caller to
hold *no* role broader than a location. That is the property that makes this
safe to roll across the write path of most of the product.

A caller with no active assignments at all resolves to an empty set, which
matches nothing. They also hold no permissions, so ``RequirePermission`` has
already refused them long before any service sees this.
"""

from __future__ import annotations

import uuid

from fastapi import Depends

from app.domains.auth.models import AuthUser

from .authorization import RoleResolver
from .dependencies import CurrentUser, get_rbac_repository
from .enums import ScopeType
from .repository import RBACRepositoryProtocol

__all__ = ["CallerLocationScope", "LocationScope", "enforce_entity_location"]

# ``None`` -- the caller is not confined to particular locations.
# A frozenset -- the caller may only act on these locations.
LocationScope = frozenset[uuid.UUID] | None

_UNCONSTRAINED_SCOPES = (ScopeType.GLOBAL, ScopeType.ORGANIZATION)


async def CallerLocationScope(
    user: AuthUser = Depends(CurrentUser),
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> LocationScope:
    """Which locations this caller may act on, or ``None`` for "any".

    See the module docstring for why this reads the caller's grants rather
    than the ``X-Location-Id`` header.
    """
    assignments = await RoleResolver(repository).get_active_assignments(
        uuid.UUID(user.id)
    )

    locations: set[uuid.UUID] = set()
    for active in assignments:
        scope_type = ScopeType(active.assignment.scope_type)
        if scope_type in _UNCONSTRAINED_SCOPES:
            return None
        if active.assignment.location_id is not None:
            locations.add(active.assignment.location_id)
    return frozenset(locations)


def enforce_entity_location(
    *,
    entity_location_id: uuid.UUID | None,
    caller_location_scope: LocationScope,
    error: Exception,
) -> None:
    """Raise ``error`` unless the caller may act on ``entity_location_id``.

    Deliberately takes the exception to raise rather than raising a shared
    one: every domain already has its own ``CrossOrganization<Thing>AccessError``
    with its own message, and a caller who is refused a firewall rule should be
    told about firewall rules.

    Two pass-through cases, both of which must stay pass-through or this locks
    real users out:

    * ``caller_location_scope is None`` -- a platform or organization-level
      caller, not confined to any site;
    * ``entity_location_id is None`` -- the row is not attached to a location
      at all (an organization-wide record), so there is no site to compare.
    """
    if caller_location_scope is None:
        return
    if entity_location_id is None:
        return
    if entity_location_id in caller_location_scope:
        return
    raise error

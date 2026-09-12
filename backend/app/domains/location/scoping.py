"""Tenant scoping for handlers that name their target location somewhere the
permission check never looked.

``RequirePermission`` resolves the scope it checks from ``_current_scope_context``
(``app.domains.rbac.dependencies``), which prefers the ``X-Location-Id``
**header** over a same-named path parameter. Two handler shapes therefore run
their permission check against one location and their read/write against
another:

1. **A location id in a query parameter.** ``GET /guests?location_id=<B>`` took
   ``location_id`` as a free ``Query`` parameter and passed only
   ``requesting_organization_id`` to the service. A front-desk account whose
   ``guest_users.read`` grant is LOCATION-scoped to site A sends
   ``X-Location-Id: A`` -- so the check passes at LOCATION scope for A -- and
   ``?location_id=B``. Both sites belong to one organization, so the
   organization-level guard sees nothing wrong, and the caller reads a sibling
   site's guest list, including guest PII.

2. **A location id in the path, with the header still winning.** ``GET
   /locations/{location_id}`` looks safe because ``_current_scope_context``
   falls back to the path parameter -- a caller sending no header is checked
   against the very location named in the URL. But the fallback is only a
   *fallback*: a caller who sends ``X-Location-Id: A`` while requesting
   ``/locations/B`` is checked against A and served B.

``app.domains.organization.scoping.enforce_target_organization`` is the same
guard one scope level up, and this module deliberately mirrors its shape and
semantics so the two read alike. The organization guard is not a substitute:
it compares organizations, and both locations in the attack above belong to
the *same* organization.

Semantics:

- a platform-level caller (``requesting_organization_id is None``) may target
  any location -- identical to ``enforce_target_organization``'s first rule,
  and it keeps a super-admin holding a stale ``X-Location-Id`` from being
  locked out of an unrelated location;
- a handler that is not narrowing to one location (``target_location_id is
  None``, e.g. ``GET /guests`` with no filter) has nothing to compare, and the
  organization-level enforcement in the service still applies;
- a caller whose permission was checked at ORGANIZATION or GLOBAL scope
  (``scope_location_id is None``) is already covered by the organization
  guard. Note that a caller holding *only* a LOCATION-scoped grant cannot
  reach this branch by simply dropping the header: ``_infer_scope_type`` would
  then resolve ORGANIZATION scope, and ``ScopeResolver.satisfies`` refuses a
  narrower grant against a broader check, so the request 403s at
  ``RequirePermission`` before any handler runs;
- otherwise the target must be exactly the location the check was run against.
"""

from __future__ import annotations

import uuid

from .exceptions import CrossLocationScopeAccessError


def enforce_target_location(
    *,
    target_location_id: uuid.UUID | None,
    scope_location_id: uuid.UUID | None,
    requesting_organization_id: uuid.UUID | None,
) -> None:
    """Raise ``CrossLocationScopeAccessError`` unless the caller may act on
    ``target_location_id``. See the module docstring for the rules.

    ``scope_location_id`` is the location the permission check actually ran
    against -- ``CurrentLocation``, i.e. the same value
    ``_current_scope_context`` handed to ``AccessValidator.check``.
    """
    if requesting_organization_id is None:
        return
    if target_location_id is None:
        return
    if scope_location_id is None:
        return
    if target_location_id == scope_location_id:
        return
    raise CrossLocationScopeAccessError()

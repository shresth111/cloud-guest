"""What "which tenant is this request about?" resolves to, and how it is asked for.

## The bug this module exists to close

``CurrentOrganization`` used to answer that question with ``uuid.UUID | None``,
and ``None`` carried two incompatible meanings at once:

1. "this caller is a platform-level admin who is deliberately reading across
   every tenant", and
2. "nobody told me which tenant, so I picked the widest possible answer".

Every service and repository in the codebase reads it as (1). The frontend
produced (2) constantly: ``services/api.ts``'s request interceptor
*deliberately skipped* attaching ``X-Organization-Id`` for any session holding
a GLOBAL-scoped role, so a founder with ``Super Admin`` looking at his own
venue's report sent no tenant at all -- and got a report blended across all
fourteen organizations in the database, most of them demo and QA fixtures.
Nothing on the screen said so. A ``total_items``, a ``success_rate_percentage``
or an ``achieved_percentage`` computed over fourteen tenants looks exactly like
one computed over one.

That is not a permissions hole -- the founder is entitled to every row he saw.
It is a *default* that answers a question nobody asked.

## The rule

"Show me every tenant" is a thing a platform admin **asks for**. It is never
what they get by accident.

:class:`OrganizationScope` splits the two meanings apart, so a request is
either about one named organization or explicitly about all of them, and
"unspecified" is no longer representable. ``CurrentOrganization`` still returns
``uuid.UUID | None`` for the ~456 call sites that consume it -- ``None`` now
*only* ever means the caller passed :data:`ALL_ORGANIZATIONS_VALUE`, which is
exactly the meaning those call sites already assume.

## How a caller asks for all organizations

``X-Organization-Scope: all`` (header), or ``?organization_scope=all`` (query
string, for a report export opened directly in a browser tab where headers
cannot be attached). Honoured **only** for a caller holding an active
GLOBAL-scoped role; anyone else asking gets a 403 rather than a silent
downgrade, because a silent downgrade is how "I thought I was looking at
everything" becomes a wrong business decision.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

__all__ = [
    "ALL_ORGANIZATIONS_VALUE",
    "ORGANIZATION_SCOPE_HEADER",
    "ORGANIZATION_SCOPE_QUERY_PARAM",
    "OrganizationScope",
]

#: Request header naming the tenancy breadth of a request.
ORGANIZATION_SCOPE_HEADER = "X-Organization-Scope"

#: Query-string equivalent of :data:`ORGANIZATION_SCOPE_HEADER`. Exists for
#: report/CSV/PDF downloads, which are opened as a plain navigation and so
#: cannot carry a custom header.
ORGANIZATION_SCOPE_QUERY_PARAM = "organization_scope"

#: The one value either of the above accepts. Compared case-insensitively
#: after stripping surrounding whitespace; anything else is treated as "not
#: asking for all organizations" rather than as an error, so a stale or
#: mistyped value fails *closed* (scoped to one tenant) instead of open.
ALL_ORGANIZATIONS_VALUE = "all"


@dataclass(frozen=True, slots=True)
class OrganizationScope:
    """The tenancy breadth a request resolved to.

    Exactly one of the two states is inhabited -- enforced in ``__post_init__``
    -- so there is no third "unspecified" state for a downstream reader to
    guess at:

    * ``organization_id`` set, ``all_organizations`` False: this request is
      about that one organization.
    * ``organization_id`` ``None``, ``all_organizations`` True: this request is
      a deliberate, explicitly-requested cross-tenant read by a caller holding
      a GLOBAL-scoped role.
    """

    organization_id: uuid.UUID | None = None
    all_organizations: bool = False

    def __post_init__(self) -> None:
        if self.all_organizations and self.organization_id is not None:
            raise ValueError(
                "OrganizationScope cannot be both all-organizations and scoped "
                "to a single organization"
            )
        if not self.all_organizations and self.organization_id is None:
            raise ValueError(
                "OrganizationScope must name an organization unless "
                "all_organizations is set"
            )

    @classmethod
    def for_organization(cls, organization_id: uuid.UUID) -> OrganizationScope:
        return cls(organization_id=organization_id, all_organizations=False)

    @classmethod
    def all(cls) -> OrganizationScope:
        return cls(organization_id=None, all_organizations=True)

    def describe(self) -> str:
        return (
            "all organizations"
            if self.all_organizations
            else f"organization {self.organization_id}"
        )


def wants_all_organizations(header_value: str | None, query_value: str | None) -> bool:
    """True when either supplied value asks for a cross-organization read.

    Split out from the FastAPI dependency so the parsing rule -- and its
    fail-closed behaviour on an unrecognised value -- is unit-testable without
    building a request.
    """
    for raw in (header_value, query_value):
        if raw is None:
            continue
        if raw.strip().casefold() == ALL_ORGANIZATIONS_VALUE:
            return True
    return False

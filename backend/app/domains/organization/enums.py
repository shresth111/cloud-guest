"""Enumerations for the Organization domain.

Stored as plain ``String`` columns on the ORM models (mirroring
``app.domains.auth.models`` -- e.g. ``User.status`` -- and
``app.domains.rbac.enums``'s documented convention) rather than native
PostgreSQL enum types, so adding a new value never requires an
``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class OrganizationType(StrEnum):
    """Discriminates a plain tenant organization from an MSP container.

    Per ``docs/rbac/RBAC_ARCHITECTURE.md``'s MSP-modeling note: there is no
    separate MSP domain/table. An MSP is simply an ``Organization`` row with
    ``org_type == MSP`` that owns other ``Organization`` rows via
    ``parent_organization_id``. A ``STANDARD`` organization may never itself
    have children (enforced in ``OrganizationService``).
    """

    STANDARD = "standard"
    MSP = "msp"


class OrganizationStatus(StrEnum):
    """Lifecycle status of an organization."""

    TRIAL = "trial"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class MembershipStatus(StrEnum):
    """Lifecycle status of a user's membership in an organization.

    Distinct from RBAC's ``user_roles`` ("what can this user do"):
    membership answers "does this user belong to this org at all".
    ``INVITED`` members have no roles/access yet -- they exist only to be
    accepted. ``SUSPENDED``/``REMOVED`` members are never resolvable as
    active without an explicit administrative transition (reactivation or a
    fresh invite respectively -- see ``OrganizationService``).
    """

    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REMOVED = "removed"

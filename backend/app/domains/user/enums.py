"""Enumerations for the User management/aggregation domain.

``UserAccountStatus`` is a typed view over ``auth.models.User.status``, the
same plain-``String``-column-not-native-enum convention every other domain
in this codebase follows (see ``app.domains.organization.enums``'s module
docstring) -- adding a new value never requires an ``ALTER TYPE``
migration. It is deliberately narrower than a full account-lifecycle enum:
only the two states this module's dedicated ``deactivate``/``activate``
endpoints actually transition between. ``auth.models.User`` itself keeps
``is_active`` (boolean, gates authentication -- see
``auth.dependencies.get_current_user``) and ``status`` (string label) as
two separate columns; this module's deactivate/reactivate flow always sets
both together (see ``app.domains.user.service.UserService``), so the two
never drift apart from each other for accounts managed through this layer.
"""

from __future__ import annotations

from enum import StrEnum


class UserAccountStatus(StrEnum):
    """The two states ``UserService.deactivate_user``/``reactivate_user``
    transition an account's ``(status, is_active)`` pair between.

    Not a copy of ``OrganizationStatus``/``LocationStatus`` -- there is no
    ``suspended``/``archived`` concept added here. A user's identity row is
    never soft-deleted by this module (``auth.models.User`` inherits
    ``BaseModel``'s soft-delete columns, but deleting a person's account
    outright is an intentionally out-of-scope, more consequential operation
    than this module's admin user-management surface takes on); the only
    two account-level transitions this domain performs are "can this person
    currently authenticate" (``ACTIVE``) and "can they not, until an admin
    reverses it" (``INACTIVE``).
    """

    ACTIVE = "active"
    INACTIVE = "inactive"

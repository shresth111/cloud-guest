"""Module 007: User management/aggregation layer.

This domain deliberately owns **no identity table of its own**. Every
identity/profile column (``first_name``, ``last_name``, ``email``,
``username``, ``phone``, ``password_hash``, ``profile_photo``,
``designation``, ``department``, ``employee_id``, ``timezone``,
``language``, ``status``, ``is_active``, ``is_verified``, etc.) already
lives on ``app.domains.auth.models.User`` (Module 003). This module is an
orchestration and read-composition layer built *on top of* that table plus
Module 005's ``OrganizationMember`` (does this user belong to an
organization) and Module 004's RBAC (what can this user do), for
administrative user-management use cases that don't belong to any single
one of those domains alone:

* Admin-driven account creation (distinct from self-service
  ``POST /auth/register``): create the identity row, optionally create an
  organization membership for it, optionally assign an initial role -- as
  one orchestrated flow instead of three disconnected API calls.
* Profile update, deactivation/reactivation (admin vs. self field
  restrictions -- see ``docs/user/USER_ARCHITECTURE.md``).
* Tenant-scoped listing/search (platform-wide vs. org-scoped), mirroring
  the scoping pattern ``app.domains.organization``/``app.domains.location``
  already established.
* An aggregated "user detail" view assembling identity + org memberships +
  active roles into one response, by composing ``app.domains.organization
  .service.OrganizationService`` and ``app.domains.rbac.authorization
  .RoleResolver`` -- never by re-querying their tables directly.

See ``backend/docs/user/USER_ARCHITECTURE.md`` for the full design,
including the narrow, targeted, additive extension made to
``app.domains.auth`` (``AuthRepositoryProtocol.list_users``) to support
this.
"""

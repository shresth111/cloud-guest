"""Module 006: Location domain (physical sites within an organization).

Builds on Module 002 (``app.database``) for persistence primitives, Module
003 (``app.domains.auth``) for identity, Module 004 (``app.domains.rbac``)
for authorization -- ``locations.*`` permission keys already seeded there
gate every mutating endpoint here -- and Module 005
(``app.domains.organization``) for hierarchy validation (a location must
belong to a real, non-archived organization; composed via
``OrganizationService``, never re-queried directly). See
``backend/docs/location/LOCATION_ARCHITECTURE.md`` for the full design.
"""

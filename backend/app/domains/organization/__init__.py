"""Module 005: Organization domain (tenants, MSP hierarchy, membership).

Builds on Module 002 (``app.database``) for persistence primitives, Module
003 (``app.domains.auth``) for identity, and Module 004
(``app.domains.rbac``) for authorization -- ``organizations.*`` permission
keys already seeded there gate every mutating endpoint here. See
``backend/docs/organization/ORGANIZATION_ARCHITECTURE.md`` for the full
design.
"""

"""Policy domain: the Unified Policy Engine -- a single source of truth for
per-organization/location-configurable policy rules (session limits,
authentication rate limits, and, structurally, bandwidth/FUP/business-hours/
access/VLAN/QoS/routing policies), their assignment to a scope, and their
versioning.

A deliberate leaf module: it depends only on ``app.domains.organization``/
``app.domains.location`` (tenant/hierarchy lookups) and ``app.domains.rbac``
(audit logging, and reusing ``ScopeType`` for assignment scoping) -- never on
``app.domains.guest``/``app.domains.guest_access``/``app.domains.voucher``/
etc. Those modules would depend on this one, never the reverse, so ``policy``
can never be part of an import cycle as more consumers are added. This
follows ``docs/ARCHITECTURE_DESIGN.md`` §6.1/§13's own design for this exact
module, written and merged into this codebase before this module itself was
built.

See ``service.py``'s module docstring for the full architectural write-up
(versioning, resolution order, why this module builds no consumer wiring
itself) and ``docs/policy/FLOW.md`` for every design decision's full
reasoning.
"""

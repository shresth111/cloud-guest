"""Module 009 Part 1: Router Provisioning (config templates/variables/
profiles/versions, provisioning queue, device-initiated enrollment +
approval, backup/restore/factory-reset, router secret rotation, and
health/event history).

Builds on Module 002 (``app.database``) for persistence primitives, Module
004 (``app.domains.rbac``) for authorization -- the already-seeded
``router_provisioning.*``/``templates.*`` permission keys gate every
mutating endpoint here, no new permission keys are invented -- and Module
008 (``app.domains.router``) for the ``Router`` device record itself,
composed via a narrow ``RouterLookupProtocol`` (never re-queried directly).
See ``backend/docs/router_provisioning/README.md`` and ``FLOW.md`` for the
full design.

This module extends BE-008's router registration/zero-touch-provisioning/
heartbeat flows with configuration management, a durable provisioning
queue, device-initiated enrollment (distinct from BE-008's admin-first
"create router, generate token" flow), backup/restore/factory-reset
actions, secret rotation, and health/event history -- it does not duplicate
or replace any of BE-008's own router-registration/check-in/heartbeat
endpoints.
"""

"""MAC Authorization domain: an organization/location-scoped MAC address
whitelist supporting permanent or temporary (expiring) authorization, with
bulk import/export.

Deliberately a standalone domain, not an extension of
``app.domains.guest_access.models.DeviceAccessRule`` (which already
covers MAC-scoped whitelist/blocklist/VIP *access-gating* precedence
rules for guest login) -- this domain's own purpose is a distinct MAC
allowlist concept, kept independent per an explicit decision to scope
this build as its own dedicated resource rather than extending an
existing domain's login-time behavior. See
``docs/mac_authorization/FLOW.md`` for the full design write-up,
including the explicit, honest scope note on how this composes (or
rather, deliberately does not yet compose) with the guest login flow.

No device/router composition -- this domain is purely
organization/location scoped, trusting ``CurrentOrganization`` the same
way ``app.domains.policy`` does (RBAC's own dependency layer already
validates real organization membership before a request reaches this
domain's service).
"""

from __future__ import annotations

"""Enumerations and small constants for the Router Agent domain.

Stored as plain ``String`` columns on :class:`~.models.RouterAgentCredential`
(``license_status``), never a native PostgreSQL enum type -- the same reason
every other domain in this codebase documents: adding a new value never
requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum

# ============================================================================
# Device-facing credential presentation
# ============================================================================

# How the persistent agent credential is presented on every device-facing
# request in this module. Deliberately a **custom header**, not the request
# body BE-008's ``POST /routers/provisioning/check-in`` precedent uses --
# see ``service.py``'s module docstring for the full reasoning (the short
# version: two of this module's five endpoints are ``GET``s, which cannot
# cleanly carry a request body, and a single presentation mechanism shared
# by all five endpoints is simpler for a real device agent to implement than
# a body-based scheme on some endpoints and a header on others). Also
# deliberately **not** ``Authorization: Bearer`` -- that header is already
# semantically owned by ``app.domains.auth``/RBAC's platform-user JWT scheme
# (``CurrentUser``), and reusing it here could tempt a future maintainer into
# wiring a device request through ``RequirePermission``/``CurrentUser`` by
# mistake. A distinctly-named header keeps the two credential spaces visibly
# separate.
AGENT_CREDENTIAL_HEADER = "X-Agent-Credential"

# Bytes of entropy (before urlsafe-base64 encoding) for a freshly-generated
# agent credential -- same order of magnitude as
# ``app.domains.router.service._TOKEN_BYTES`` (provisioning tokens) and
# ``app.domains.router_provisioning.constants.ROTATED_SECRET_BYTES`` (router
# secret rotation).
AGENT_CREDENTIAL_BYTES = 32

# How long a persistent agent credential remains valid before it must be
# reissued (e.g. via a factory-reset -> re-provision -> check-in cycle,
# which rotates it). Unlike the one-time provisioning token (hours-scale,
# see ``Settings.router_provisioning_token_expire_hours``), this credential
# is meant to back *every* ongoing device call for the router's operational
# lifetime, so it defaults to a long, year-scale TTL rather than an
# hours-scale one. A plain module constant (not a ``Settings`` field) --
# this module's scope is deliberately limited to its own directory plus a
# short, named list of additive edits elsewhere; wiring a new environment
# variable through ``app.core.config.Settings`` is not one of them, and a
# constructor-level default (``RouterAgentService.__init__``) is enough to
# keep the value overridable in tests without touching global config.
AGENT_CREDENTIAL_TTL_DAYS = 365


class AgentLicenseStatus(StrEnum):
    """The agent's self-reported CloudGuest license state, submitted via
    ``POST /agent/status``. A genuinely new fact -- no existing field on
    ``Router``/``RouterProvisioning`` models captures license state, unlike
    ``routeros_version`` (already ``Router.routeros_version``, reused
    as-is, never duplicated here)."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class RouterAgentEventType(StrEnum):
    """``event_type`` values this module writes to
    ``app.domains.router_provisioning.models.RouterEvent`` (composed via a
    narrow ``RouterEventWriter`` protocol -- see ``service.py``, never a
    second event table).

    Deliberately a **separate** ``StrEnum`` from that module's own
    ``router_provisioning.constants.RouterEventType`` rather than an edit to
    it: ``RouterEvent.event_type`` is a plain ``String(30)`` column with no
    database ``CHECK`` tying it to any one enum (mirrors this codebase's
    "plain string, not a native enum type" convention, documented in that
    module's own ``constants.py``), so a second, additive ``StrEnum`` of new
    values composes cleanly without ever touching a file outside this
    module's own directory.
    """

    CREDENTIAL_ISSUED = "agent_credential_issued"
    STATUS_REPORTED = "agent_status_reported"


__all__ = [
    "AGENT_CREDENTIAL_HEADER",
    "AGENT_CREDENTIAL_BYTES",
    "AGENT_CREDENTIAL_TTL_DAYS",
    "AgentLicenseStatus",
    "RouterAgentEventType",
]

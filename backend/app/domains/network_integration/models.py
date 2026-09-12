"""SQLAlchemy ORM models for the Network Integration domain.

Three tables, and the split between them is the design:

* ``network_integrations`` -- **current state.** One row per (tenant,
  controller, site). A row's own columns *are* the truth about that
  integration right now; there is no history here.
* ``network_integration_events`` -- **append-only operational feed.** Why
  the current state is what it is. Never updated, only inserted.
* ``network_integration_authorizations`` -- **append-only record of what
  this platform asked a controller to do** for one guest.

## Why the events table exists at all, next to ``audit_log_entries``

They answer different questions and neither substitutes for the other.

``audit_log_entries`` is the platform-wide compliance trail: *which human
did what*. Every human-caused action here writes one, through the existing
audit domain, exactly as every other domain does -- no second audit table.

But most of what happens to an integration is not caused by a human. A
background sync failing at 03:00 has no ``actor_user_id`` to record, and a
venue owner debugging "why did guest WiFi stop working last night" should
not be handed their organization's entire RBAC audit log to search
through. This feed is scoped to one integration, contains machine events
as first-class rows, and is what ``GET /{id}/events`` renders. That is a
genuinely different read, not a duplicate of the same one.

## Why ``organization_id`` is denormalized onto all three

``network_integration_events.organization_id`` and
``network_integration_authorizations.organization_id`` are both derivable
by joining back to ``network_integrations``. They are stored anyway, for
the same reason ``app.domains.guest.models.GuestSession.organization_id``
is (see that column's own docstring): every read of these tables is
tenant-scoped on every call, and the denormalized column lets the
tenant filter be an indexed equality rather than a join on every query.
Immutable after insert, like Router's and GuestSession's copies.

There is a second, sharper reason here. The tenant filter is a *security*
control on these tables, and a security control that depends on a join is
one that a future query can accidentally omit while still returning rows.
An ``organization_id`` column on the row being read makes the filter local
to the query that needs it.

## Why ``credentials_encrypted`` is one Text column

Fernet ciphertext of a JSON credential set -- see
``crypto.py``'s module docstring for why one column rather than four
nullable encrypted ones, and why a separate key from
``router_encryption_key``. Nothing outside ``crypto.py`` and ``service.py``
touches this column, no endpoint returns it, and no schema in
``schemas.py`` has a field for it: the API exposes ``has_credentials:
bool`` and nothing else.

## Soft delete, and what the partial unique index actually promises

All three tables extend ``BaseModel``, so they carry
``is_deleted``/``deleted_at``. The uniqueness constraint on
``network_integrations`` is therefore partial --
``WHERE is_deleted = false``. That means: within one organization, one
provider may have at most one *live* row per ``(base_url,
external_site_id)``. A venue that deletes an integration and re-adds the
same controller+site later gets a fresh row, and the old one stays
readable for its audit trail. Postgres treats every NULL as distinct, so
a row with no site selected yet (``external_site_id IS NULL``) does not
conflict with another such row -- deliberately: two half-finished connect
wizards against the same controller are not yet a duplicate of anything,
and refusing the second would break the wizard.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    DEFAULT_CONTROLLER_TLS_MODE,
    DEFAULT_PORTAL_AUTH_MODE,
    DEFAULT_SESSION_DURATION_SECONDS,
    DEFAULT_SYNC_INTERVAL_SECONDS,
    AuthorizationStatus,
    ControllerAuthMode,
    IntegrationStatus,
    NetworkProviderKind,
    SyncStatus,
)

__all__ = [
    "NetworkIntegration",
    "NetworkIntegrationAuthorization",
    "NetworkIntegrationEvent",
]


class NetworkIntegration(BaseModel):
    """One tenant's connection to one third-party network controller site."""

    __tablename__ = "network_integrations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL means "not mapped to a venue", and nothing more than that.
    #
    # This comment used to open with "NULL = organization-wide (a
    # controller that serves several of the tenant's venues)". That
    # semantic is not implemented anywhere: the portal authorize path
    # resolves an integration by an EXACT (organization, location,
    # provider) match, so a NULL here is selected for no venue at all --
    # not for all of them. Reading it as organization-wide is exactly how
    # an operator ends up with a controller that looks configured and
    # authorizes nobody, so the wording is corrected rather than left to
    # be discovered.
    #
    # `PortalReadinessGap.LOCATION_NOT_MAPPED` is the surfacing of it:
    # `_sync` refuses to call such a row CONNECTED and the readiness
    # checklist fails its CONTROLLER_INTEGRATION item.
    #
    # `MODULE_NARROWEST_SCOPE[NETWORK_INTEGRATIONS] = LOCATION` follows
    # from this column being nullable, exactly as it does for
    # PermissionModule.NETWORK_DEVICE.
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    # The fleet-inventory row representing this controller, when one
    # exists. Contract §11.3.
    #
    # ## Why an Omada controller is also a `Router` row
    #
    # Not because a controller is a router -- it emphatically is not, and
    # `providers/base.py` exists precisely to stop this domain being forced
    # through the router-shaped 30-method Protocol. It is because
    # `guest_sessions.router_id` is NOT NULL, so at an Omada-only venue
    # (which has no MikroTik hardware in the path at all) a guest could not
    # log in *at all* without one. Making that column nullable was the
    # alternative and was rejected: it is the busiest table in the product
    # and every downstream consumer assumes non-null.
    #
    # ## Nullable, and it must stay nullable
    #
    # A customer self-service integration created from the Customer
    # Dashboard has no fleet row -- it is an integration, not a device the
    # platform provisioned. Only the Master-driven onboarding path
    # (`create_integration_with_fleet_device`) creates the pair. Requiring
    # it would break self-service; defaulting it would fabricate a device.
    #
    # ## The honesty cost, stated here because it is real
    #
    # The linked `Router` row is synthetic: no `router_agent` will ever
    # check in for it, there is no RouterOS API on 8728, and there is no
    # WireGuard tunnel. Several MikroTik-assuming surfaces would therefore
    # report it as offline/unhealthy. This domain keeps that row in a state
    # where the RouterOS-assuming sweeps are inert by construction (NULL
    # API credentials, `snmp_enabled=False`, never `ONLINE`) rather than
    # relying on every one of those surfaces remembering to check the
    # vendor -- see `service.create_integration_with_fleet_device`. That is
    # a mitigation, not a complete fix; the remaining surfaces are
    # enumerated in this domain's own `__init__.py`.
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Plain string, not a native PG enum -- the same "no native enum"
    # posture every other status/kind column in this codebase takes, so
    # adding a second provider is a code change and not a migration.
    provider: Mapped[str] = mapped_column(
        String(30), default=NetworkProviderKind.OMADA.value, nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default=IntegrationStatus.UNCONFIGURED.value, nullable=False
    )
    # Two separate flags, not one. `is_enabled` is the operator's
    # intention ("this integration should be working"); `status` is the
    # observed reality. Folding them together would make "disabled" and
    # "broken" the same value, and then re-enabling an integration would
    # have nothing to restore it to.
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Normalized by validators.validate_controller_url before this row is
    # ever written: lowercase scheme+host, explicit port, no path. Safe to
    # show a customer -- it is what they typed.
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_mode: Mapped[str] = mapped_column(
        String(20), default=ControllerAuthMode.OPENAPI.value, nullable=False
    )
    # The controller's own `omadacId`, discovered on first successful
    # connection (GET /api/info) rather than typed in. Nullable until then.
    controller_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    controller_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_site_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Cached alongside the id purely so a list view can render a site name
    # without a live controller call per row. Refreshed on every sync; may
    # be stale between them, and a stale *name* next to a correct *id* is
    # a cosmetic problem, which is why only the id is ever sent to the
    # controller.
    external_site_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    guest_ssid_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    guest_ssid_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # How much this platform trusts the certificate the controller
    # presents: 'strict', 'pinned' or 'insecure'. See
    # constants.ControllerTlsMode for why three values rather than the
    # boolean this used to (not) be.
    #
    # server_default is the point of the column: every row that predates it
    # gets 'strict', which is exactly what those rows did before it existed
    # (the old verify_tls flag was unreachable and therefore permanently
    # True). The migration changes no integration's behaviour.
    tls_mode: Mapped[str] = mapped_column(
        String(20),
        default=DEFAULT_CONTROLLER_TLS_MODE.value,
        server_default=DEFAULT_CONTROLLER_TLS_MODE.value,
        nullable=False,
    )
    # Lowercase hex SHA-256 of the controller certificate's DER encoding,
    # when tls_mode is 'pinned'. NULL otherwise, and cleared when the mode
    # moves away from 'pinned' -- a pin that is stored but not consulted
    # reads to the next person as a guarantee that is not being made.
    #
    # Not encrypted, and that is correct rather than an oversight: this is a
    # hash of a certificate the controller hands to anyone who opens a
    # socket to it. Encrypting public data would only make it harder to show
    # the operator what they pinned.
    tls_pinned_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # When somebody last made an explicit trust decision about this
    # controller. NULL means "nobody has; this is the strict default".
    # Who made it lives in the audit log, which is the thing designed to
    # hold an actor and cannot be overwritten by the next decision.
    tls_trust_decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # WHICH CAPTIVE-PORTAL CONTRACT THIS VENUE IS ON -- 'external_portal'
    # (TP-Link authType 4) or 'radius' (authType 2 + External Web Portal).
    # See constants.PortalAuthMode for what each one actually does and why
    # the answer is stored rather than sniffed off a redirect's parameters.
    #
    # Three surfaces dispatch on this one column and none of them guesses:
    # `validators.build_external_portal_url` (what the operator pastes into
    # the controller), `service.authorize_portal_client` (which refuses
    # outright in RADIUS mode -- this platform is not in that path) and
    # `service.disconnect_guest` (whose two modes revoke by different
    # mechanisms with genuinely different guarantees).
    #
    # server_default is the point of the column, exactly as it is for
    # `tls_mode`: every row that predates it gets 'external_portal', which
    # is what those rows have always done. The migration changes no
    # integration's behaviour, and no code path turns RADIUS mode on by
    # itself -- it is set deliberately, by a platform operator, on a venue
    # whose network path has been arranged first.
    portal_mode: Mapped[str] = mapped_column(
        String(30),
        default=DEFAULT_PORTAL_AUTH_MODE.value,
        server_default=DEFAULT_PORTAL_AUTH_MODE.value,
        nullable=False,
    )
    # Fernet ciphertext of a JSON credential set. See crypto.py. Never
    # returned by any endpoint; never logged.
    credentials_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_duration_seconds: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_SESSION_DURATION_SECONDS, nullable=False
    )
    sync_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_SYNC_INTERVAL_SECONDS, nullable=False
    )
    # Provider-shaped extras that do not deserve a column each: cached
    # device/client counts from the last sync, the consecutive-failure
    # counter the backoff reads, and whatever a future provider needs to
    # remember. Deliberately not a place for anything a query has to
    # filter on -- those get real columns.
    provider_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_status: Mapped[str] = mapped_column(
        String(20), default=SyncStatus.NEVER.value, nullable=False
    )
    # The most recent failure, kept on the row so a list view can show
    # "why is this red" without reading the events table per row. The
    # events table remains the full history; these three columns are the
    # latest entry, denormalized for the list.
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_network_integrations_organization_id", "organization_id"),
        Index("ix_network_integrations_location_id", "location_id"),
        Index("ix_network_integrations_provider_status", "provider", "status"),
        Index("ix_network_integrations_is_enabled", "is_enabled"),
        Index("ix_network_integrations_router_id", "router_id"),
        Index(
            "uq_network_integrations_org_provider_base_url_site",
            "organization_id",
            "provider",
            "base_url",
            "external_site_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        # No base_url, no credentials. A repr lands in tracebacks and log
        # lines; the id and the status are enough to find the row.
        return (
            f"<NetworkIntegration(id={self.id}, provider={self.provider}, "
            f"status={self.status})>"
        )


class NetworkIntegrationEvent(BaseModel):
    """One entry in an integration's operational feed. Append-only.

    ``message`` and ``context`` are **pre-redacted at write time** by
    ``service.py`` (see ``constants.REDACTED_CONTEXT_KEYS``). This is not a
    logging concern: these two columns are rendered straight into the
    customer dashboard, so a secret that reaches them has already left the
    building by the time any log filter would see it.
    """

    __tablename__ = "network_integration_events"

    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_integrations.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )

    __table_args__ = (
        Index("ix_network_integration_events_integration_id", "integration_id"),
        Index("ix_network_integration_events_organization_id", "organization_id"),
        Index("ix_network_integration_events_event_type", "event_type"),
        # `created_at` is already indexed by TimestampMixin. This composite
        # is what the feed query actually uses -- one integration's events,
        # newest first -- and it is the difference between an index scan
        # and a sort over every event the tenant has ever produced.
        Index(
            "ix_network_integration_events_integration_created",
            "integration_id",
            "created_at",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<NetworkIntegrationEvent(id={self.id}, "
            f"event_type={self.event_type}, status={self.status})>"
        )


class NetworkIntegrationAuthorization(BaseModel):
    """One record of this platform asking a controller to let one guest on.

    Append-only in spirit: a row is inserted when the authorization is
    attempted and only ever updated to record a *later* deauthorization.
    Nothing rewrites the original attempt.

    ## This table is not a mirror of controller state

    Worth being blunt, because the column names invite the opposite
    reading. ``status``/``expires_at`` record *what this platform asked
    for and what the controller said at that moment*. The controller can
    subsequently expire, revoke or lose the authorization with no
    notification -- Omada's controller API has no webhook for this (see
    ``tasks.py``) -- so a row reading ``authorized`` with a future
    ``expires_at`` means "we asked, and it was accepted", not "this device
    is on the internet right now". Any UI that renders it as live state is
    overstating what this platform knows.

    ``guest_session_id`` is ``ON DELETE SET NULL`` rather than CASCADE: a
    guest session being purged (retention, a GDPR erasure) must not delete
    the record that this platform reached into a customer's controller. The
    authorization row survives with a null session reference, which is the
    honest outcome -- the action happened, the subject's record did not.
    """

    __tablename__ = "network_integration_authorizations"

    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_integrations.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    guest_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Canonical uppercase colon-separated form -- normalized by
    # validators.normalize_client_mac before the row is written.
    client_mac: Mapped[str] = mapped_column(String(17), nullable=False)
    ap_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    ssid_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_site_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default=AuthorizationStatus.AUTHORIZED.value, nullable=False
    )
    authorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deauthorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index(
            "ix_network_integration_authorizations_integration_status",
            "integration_id",
            "status",
        ),
        Index(
            "ix_network_integration_authorizations_org_authorized_at",
            "organization_id",
            "authorized_at",
        ),
        Index("ix_network_integration_authorizations_client_mac", "client_mac"),
        Index(
            "ix_network_integration_authorizations_location_id", "location_id"
        ),
        Index(
            "ix_network_integration_authorizations_guest_session_id",
            "guest_session_id",
        ),
    )

    def __repr__(self) -> str:
        # No client_mac: a MAC address is guest PII in this codebase (see
        # app.common.masking.MaskedMac) and a repr is exactly where it
        # would leak into a log unmasked.
        return (
            f"<NetworkIntegrationAuthorization(id={self.id}, "
            f"status={self.status})>"
        )

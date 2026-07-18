"""SQLAlchemy ORM models for the Monitoring domain (BE-011 Part 1: Health
Engine + Event Engine).

All tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

This module is deliberately **platform-wide / cross-domain**, not a second
copy of per-router monitoring. BE-008 (``app.domains.router``) already
persists a router's *current* snapshot (``Router.health_status``/
``last_seen_at``/``last_health_check_at``) and BE-009
(``app.domains.router_provisioning``) already persists that router's
*history* (``RouterHealthSnapshot``, time-series metrics;
``RouterEvent``, device telemetry/lifecycle log). Nothing here duplicates
either. Three tables are defined:

* :class:`HealthCheck` -- one row per health-check *execution* for one of
  this module's own ``constants.HealthComponent`` values (database, redis,
  the API process itself, auth, storage, celery, websocket, freeradius,
  wireguard) -- the time-series history a dashboard's "show me the last 24
  hours of database latency" view would read.
* :class:`ServiceHealth` -- one row *per component* (unique), the current
  rolled-up state a dashboard's "what is healthy right now" view reads
  without scanning ``HealthCheck`` history on every request. Mirrors
  ``Router``'s own "current snapshot column vs. separate history table"
  split, one level up (platform components, not one router).
* :class:`HeartbeatLog` -- a generic, cross-domain heartbeat *log*, not a
  per-domain heartbeat mechanism (see its own docstring below for the full
  design write-up and its precise relationship to
  ``app.domains.router_agent``'s existing device heartbeat).
* :class:`PlatformEvent` -- a narrowly-scoped **new** event table, populated
  only by this module's own Health Engine (component status transitions) --
  see its own docstring below for why this is *not* a duplicate of RBAC's
  ``audit_log_entries`` or ``router_provisioning``'s ``RouterEvent``, and
  exactly how ``service.get_event_timeline`` merges all three into one
  read-side view without copying either existing table's data into this
  one.

## Why there is no ``DeviceHealth`` table (a deliberate non-decision)

The module brief invited a router-level health "rollup" table here. After
reading ``app.domains.router.models.Router`` and
``app.domains.router_provisioning.models.RouterHealthSnapshot``/
``RouterEvent`` in full, the conclusion is that **no new table, and not even
a new composition method, earns its keep in this Part 1**:

* "What is this router's health *right now*" is already exactly
  ``Router.health_status``/``last_seen_at``/``last_health_check_at`` --
  three plain columns on the row BE-008 already maintains on every
  heartbeat.
* "What was this router's health *over time*" is already exactly
  ``RouterHealthSnapshot`` (a full time-series table:
  ``cpu_usage_percent``/``memory_usage_percent``/``uptime_seconds``/
  ``connected_clients_count``, paginated by
  ``RouterProvisioningRepository.list_health_snapshots_for_router``) and
  ``RouterEvent`` (reboot/config-applied/error/enrollment history).
* A ``DeviceHealth`` table here would therefore either (a) duplicate every
  one of those columns for zero new information captured, or (b) be a thin
  read-only view joining ``Router``+``RouterHealthSnapshot`` -- which is
  just as easily (and more honestly) expressed as "call
  ``RouterService.get_router`` and
  ``RouterProvisioningRepository.list_health_snapshots_for_router``
  directly," something every caller (a future ZTP/analytics dashboard,
  BE-011 Part 3) can already do today with zero code added here.

This module's own dashboard (``GET /monitoring/health``) is scoped entirely
to platform-level components (database/redis/API/auth/storage/celery/
websocket/freeradius/wireguard) -- a per-router breakdown is a different
question that ``router_provisioning``'s own existing endpoints already
answer completely. Revisit only if a genuine cross-router *aggregate* need
emerges that neither domain currently answers (even "how many routers are
unhealthy platform-wide" is a single ``COUNT(...) WHERE health_status =
'unhealthy'`` query against the existing ``routers`` table, not a reason for
a new persisted table).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class HealthCheck(BaseModel):
    """One row per health-check execution for one platform component -- the
    time-series history :class:`ServiceHealth`'s "current state" rollup
    deliberately does not keep (mirrors ``RouterHealthSnapshot`` vs.
    ``Router.health_status``'s identical split, one level up)."""

    __tablename__ = "health_checks"

    component: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_health_checks_component", "component"),
        Index("ix_health_checks_status", "status"),
        Index("ix_health_checks_checked_at", "checked_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<HealthCheck(component={self.component}, status={self.status}, "
            f"checked_at={self.checked_at})>"
        )


class ServiceHealth(BaseModel):
    """One row *per component* (unique), the current rolled-up state a
    dashboard reads without scanning :class:`HealthCheck` history on every
    request. ``consecutive_failure_count`` increments on every non-``healthy``
    result and resets to zero the moment a component reports ``healthy``
    again -- see ``service.py``'s ``_persist_result`` for the exact
    increment/reset logic, and BE-011 Part 2 (alerting) for the intended
    future consumer of this column (an alert threshold on N consecutive
    failures)."""

    __tablename__ = "service_health"

    component: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_failure_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    __table_args__ = (
        Index("ix_service_health_component", "component", unique=True),
        Index("ix_service_health_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<ServiceHealth(component={self.component}, status={self.status})>"


class HeartbeatLog(BaseModel):
    """A generic, cross-domain heartbeat *log* for the monitoring
    dashboard's unified timeline -- **not** a replacement for any existing
    domain's own heartbeat mechanism.

    ``component_id`` is a plain ``UUID`` column with **no** SQL foreign key,
    because it polymorphically refers to a different table depending on
    ``component_type`` (``constants.HeartbeatComponentType`` --
    ``routers.id`` for ``ROUTER``, ``wireguard_peers.id`` for
    ``WIREGUARD_PEER``, an opaque platform-service identifier for
    ``SERVICE``). A single SQL FK cannot reference more than one table, and
    a separate nullable FK column per component type would grow this table's
    schema with every new component type added -- the exact same tradeoff
    ``app.domains.rbac.models``'s scope columns and this codebase's own
    ``entity_type``/``entity_id`` pattern on ``AuditLogEntry`` already
    accept for the identical reason. This is a common, legitimate pattern
    for cross-cutting logs (an audit/telemetry sink over heterogeneous
    sources), not an oversight -- referential integrity for "does this
    row's ``component_id`` still exist" is intentionally not enforced at
    the database level, the same tradeoff ``AuditLogEntry.entity_id``
    already makes.

    ## Relationship to ``app.domains.router_agent``'s existing heartbeat

    ``app.domains.router_agent``'s ``POST /agent/heartbeat`` endpoint
    already updates BE-008's ``Router.last_seen_at`` (via
    ``RouterAgentService.heartbeat`` -> ``RouterService.heartbeat``) on
    every real device heartbeat, and that is still the *only* mechanism
    that flips a router's liveness/online status -- this table changes none
    of that. What this table adds is a **platform-wide, cross-component
    log** of the same moment, for a monitoring dashboard's unified timeline
    that also wants to show WireGuard/future-service heartbeats
    side-by-side with router heartbeats without querying N different
    domains' tables and merging them client-side. The decision made here:
    ``app.domains.router_agent.router.agent_heartbeat`` gets one small,
    additive call (after its existing ``RouterAgentService.heartbeat``
    call) into this module's own ``MonitoringService.record_heartbeat`` --
    composing with the existing heartbeat handler, not duplicating its
    logic or its liveness-detection responsibility. See that endpoint's
    updated docstring in ``app/domains/router_agent/router.py`` for the
    precise, minimal edit, and ``constants.HeartbeatComponentType``'s
    docstring for why ``WIREGUARD_PEER`` is defined but has no writer yet in
    this iteration (this module's directory rule budgeted exactly one
    additive cross-domain hook, spent on the router-agent seam, which
    reaches far more devices than WireGuard's still-optional tunnel).
    """

    __tablename__ = "heartbeat_logs"

    component_type: Mapped[str] = mapped_column(String(20), nullable=False)
    component_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_heartbeat_logs_component_type", "component_type"),
        Index("ix_heartbeat_logs_component_id", "component_id"),
        Index("ix_heartbeat_logs_received_at", "received_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<HeartbeatLog(component_type={self.component_type}, "
            f"component_id={self.component_id})>"
        )


class PlatformEvent(BaseModel):
    """A platform-wide, cross-domain event **narrowly scoped to what is
    genuinely new**: this module's own Health Engine's detected component
    status transitions (e.g. "database health transitioned to
    unhealthy"). It is deliberately **not** a general-purpose duplicate of
    every domain's own event logging.

    ## Composition-vs-new-storage decision (read this before adding a row
    here from another domain)

    Two tables already log domain events, each with its own well-justified
    scope: RBAC's ``audit_log_entries`` (accountable, human-attributable,
    moderate-volume *admin actions* -- "who did what, when, to which
    entity") and ``router_provisioning``'s ``RouterEvent`` (high-volume,
    often-no-human-actor *device telemetry* for one router). Both are
    already, individually, the right table for the events they carry --
    duplicating either one's rows into a second table here would be pure
    storage duplication for zero new signal, and would immediately drift
    out of sync with whichever table stays the actual source of truth.

    The architectural call made here: ``PlatformEvent`` exists **only** for
    events that do not already have a home in either of those tables --
    concretely, in this Part 1, that means exactly this module's own
    Health Engine's status-transition detections (see ``service.py``'s
    ``_record_transition_event``), which nothing else in this codebase
    currently records anywhere. ``get_event_timeline`` (``service.py``) is
    the actual **unified timeline** the module brief asked for: a read-side
    aggregation that queries this table *and* ``audit_log_entries`` *and*
    ``RouterEvent`` directly (via read-only ``SELECT``s against their
    already-defined models -- no code in ``rbac``/``router_provisioning``
    is touched to make this work) and merges all three into one
    chronologically-sorted list at request time. This means: zero duplicate
    storage, zero cross-domain writes into another domain's table, and a
    genuinely new (if narrow) table that captures a real gap no existing
    table filled. A future domain that wants its own moments on this
    platform-wide timeline can call
    ``MonitoringService.record_platform_event`` directly (the same
    "``ServiceX`` composes with ``ServiceY`` through a narrow surface"
    pattern every other domain in this codebase already uses) -- but no
    such call was added to any other domain's files in this iteration
    (out of this module's own directory-rule scope), so today's only
    writer is this module itself.

    Columns mirror the module brief exactly: ``category``
    (``constants.EventCategory``), ``event_type`` (a free-form namespaced
    string, e.g. ``"monitoring.component_unhealthy"`` -- deliberately not a
    closed enum, since event types will grow across every domain over
    time, the same reasoning ``RouterEvent.event_type`` already documents),
    ``severity`` (``constants.EventSeverity``), optional
    ``organization_id``/``location_id``/``router_id`` scope (all ``NULL``
    for this module's own platform-wide health-transition events, but
    present on the schema for any future domain-scoped writer),
    ``source_domain`` (a plain string identifying the writer -- always
    ``"monitoring"`` today), ``message``, ``metadata`` (JSONB, the Python
    attribute is ``event_metadata`` -- ``metadata`` is reserved by
    SQLAlchemy's ``DeclarativeBase``, mirroring ``AuditLogEntry``/
    ``RouterEvent``'s identical convention), and ``occurred_at``.
    """

    __tablename__ = "platform_events"

    category: Mapped[str] = mapped_column(String(20), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_domain: Mapped[str] = mapped_column(String(50), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB, nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_platform_events_category", "category"),
        Index("ix_platform_events_event_type", "event_type"),
        Index("ix_platform_events_severity", "severity"),
        Index("ix_platform_events_organization_id", "organization_id"),
        Index("ix_platform_events_location_id", "location_id"),
        Index("ix_platform_events_router_id", "router_id"),
        Index("ix_platform_events_occurred_at", "occurred_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<PlatformEvent(category={self.category}, "
            f"event_type={self.event_type}, severity={self.severity})>"
        )


__all__ = [
    "HealthCheck",
    "ServiceHealth",
    "HeartbeatLog",
    "PlatformEvent",
]

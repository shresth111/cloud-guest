"""Data access layer for the Monitoring domain (BE-011 Part 1).

Mirrors ``app.domains.guest.repository``'s shape: a ``Protocol`` describing
the operations the service layer needs (``MonitoringRepositoryProtocol``),
and a concrete, mostly-``GenericRepository``-backed implementation
(``MonitoringRepository``), plus hand-written ``select`` statements for two
kinds of query ``GenericRepository``'s equality-filter support cannot
express: (a) the event-timeline's read-side aggregation across *other*
domains' own tables (``AuditLogEntry``, ``RouterEvent``), and (b) the
FreeRADIUS/WireGuard proxy-signal composition queries against ``guest``'s/
``wireguard``'s own tables.

## Reading other domains' tables directly -- composition, not duplication

``list_audit_log_events``/``list_router_events``/
``count_active_radius_nas_clients``/``get_latest_guest_accounting_activity``/
``list_wireguard_peers`` all import and query another domain's *model*
directly (read-only ``SELECT``s), never that domain's service or repository
layer. This is the same precedent
``app.domains.rbac.dependencies.CurrentOrganization``/``CurrentLocation``
already establish (querying ``Organization``/``Location`` directly via a
bare ``GenericRepository`` rather than going through
``OrganizationService``/``LocationService``) -- a narrow, read-only,
cross-domain lookup that doesn't warrant standing up each domain's full
service layer just to read a few rows for an aggregate/dashboard signal. No
file inside ``rbac``/``router_provisioning``/``guest``/``wireguard`` is
edited to make this work.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.domains.guest.models import GuestSession, RadiusNasClient
from app.domains.rbac.models import AuditLogEntry
from app.domains.router.models import Router
from app.domains.router_provisioning.constants import ProvisioningJobStatus
from app.domains.router_provisioning.models import (
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)
from app.domains.wireguard.models import WireGuardPeer

from .constants import AlertStatus
from .models import (
    Alert,
    AlertRule,
    AlertRuleNotificationChannel,
    HealthCheck,
    HeartbeatLog,
    Incident,
    IncidentAlert,
    NotificationChannel,
    NotificationLog,
    PlatformEvent,
    ServiceHealth,
    SlaReport,
    SlaTarget,
)


class MonitoringRepositoryProtocol(Protocol):
    # -- health checks -----------------------------------------------------
    async def ping_database(self) -> None: ...

    async def create_health_check(self, **fields: object) -> HealthCheck: ...

    async def list_health_checks(
        self, *, component: str, page: int, page_size: int
    ) -> tuple[list[HealthCheck], PaginationMeta]: ...

    # -- service health rollup ----------------------------------------------
    async def get_service_health(self, component: str) -> ServiceHealth | None: ...

    async def create_service_health(self, **fields: object) -> ServiceHealth: ...

    async def update_service_health(
        self, service_health: ServiceHealth, data: dict[str, object]
    ) -> ServiceHealth: ...

    async def list_service_health(self) -> list[ServiceHealth]: ...

    # -- heartbeats -----------------------------------------------------------
    async def create_heartbeat_log(self, **fields: object) -> HeartbeatLog: ...

    # -- platform events -----------------------------------------------------
    async def create_platform_event(self, **fields: object) -> PlatformEvent: ...

    async def list_platform_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        categories: list[str] | None,
        severities: list[str] | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[PlatformEvent]: ...

    # -- read-side composition for the unified event timeline ----------------
    async def list_audit_log_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[AuditLogEntry]: ...

    async def list_router_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[RouterEvent]: ...

    # -- FreeRADIUS proxy signal (composes with app.domains.guest) ------------
    async def count_active_radius_nas_clients(self) -> int: ...

    async def get_latest_guest_accounting_activity(self) -> datetime | None: ...

    # -- WireGuard proxy signal (composes with app.domains.wireguard) --------
    async def list_wireguard_peers(self) -> list[WireGuardPeer]: ...

    # -- alert rules -----------------------------------------------------------
    async def create_alert_rule(self, **fields: object) -> AlertRule: ...

    async def get_alert_rule(self, rule_id: uuid.UUID) -> AlertRule | None: ...

    async def update_alert_rule(
        self, rule: AlertRule, data: dict[str, object]
    ) -> AlertRule: ...

    async def soft_delete_alert_rule(self, rule: AlertRule) -> AlertRule: ...

    async def list_alert_rules(
        self,
        *,
        organization_id: uuid.UUID | None,
        is_active: bool | None,
        page: int,
        page_size: int,
    ) -> tuple[list[AlertRule], PaginationMeta]: ...

    async def list_active_alert_rules(self) -> list[AlertRule]: ...

    async def add_alert_rule_notification_channel(
        self, alert_rule_id: uuid.UUID, notification_channel_id: uuid.UUID
    ) -> AlertRuleNotificationChannel: ...

    async def replace_alert_rule_notification_channels(
        self, alert_rule_id: uuid.UUID, notification_channel_ids: list[uuid.UUID]
    ) -> None: ...

    async def list_notification_channel_ids_for_rule(
        self, alert_rule_id: uuid.UUID
    ) -> list[uuid.UUID]: ...

    # -- alerts ------------------------------------------------------------
    async def create_alert(self, **fields: object) -> Alert: ...

    async def get_alert(self, alert_id: uuid.UUID) -> Alert | None: ...

    async def update_alert(self, alert: Alert, data: dict[str, object]) -> Alert: ...

    async def list_alerts(
        self,
        *,
        organization_id: uuid.UUID | None,
        status: str | None,
        severity: str | None,
        router_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Alert], PaginationMeta]: ...

    async def find_active_alert(
        self,
        *,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
    ) -> Alert | None: ...

    async def find_alert_by_related_event(
        self, *, rule_id: uuid.UUID, related_event_id: uuid.UUID
    ) -> Alert | None: ...

    # -- alert-rule evaluation composition (read-only, other domains) --------
    async def list_routers(
        self, *, organization_id: uuid.UUID | None
    ) -> list[Router]: ...

    async def get_latest_router_health_snapshot(
        self, router_id: uuid.UUID
    ) -> RouterHealthSnapshot | None: ...

    async def list_recent_platform_events(
        self,
        *,
        event_type: str,
        organization_id: uuid.UUID | None,
        since: datetime,
    ) -> list[PlatformEvent]: ...

    # -- notification channels -----------------------------------------------
    async def create_notification_channel(
        self, **fields: object
    ) -> NotificationChannel: ...

    async def get_notification_channel(
        self, channel_id: uuid.UUID
    ) -> NotificationChannel | None: ...

    async def update_notification_channel(
        self, channel: NotificationChannel, data: dict[str, object]
    ) -> NotificationChannel: ...

    async def soft_delete_notification_channel(
        self, channel: NotificationChannel
    ) -> NotificationChannel: ...

    async def list_notification_channels(
        self,
        *,
        organization_id: uuid.UUID | None,
        channel_type: str | None,
        is_active: bool | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationChannel], PaginationMeta]: ...

    async def get_notification_channels_by_ids(
        self, channel_ids: list[uuid.UUID]
    ) -> list[NotificationChannel]: ...

    # -- notification logs ---------------------------------------------------
    async def create_notification_log(self, **fields: object) -> NotificationLog: ...

    async def list_notification_logs(
        self,
        *,
        channel_id: uuid.UUID | None,
        alert_id: uuid.UUID | None,
        status: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationLog], PaginationMeta]: ...

    # -- incidents -------------------------------------------------------------
    async def create_incident(self, **fields: object) -> Incident: ...

    async def get_incident(self, incident_id: uuid.UUID) -> Incident | None: ...

    async def update_incident(
        self, incident: Incident, data: dict[str, object]
    ) -> Incident: ...

    async def list_incidents(
        self,
        *,
        organization_id: uuid.UUID | None,
        status: str | None,
        severity: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Incident], PaginationMeta]: ...

    async def incident_alert_exists(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> bool: ...

    async def attach_alert_to_incident(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> IncidentAlert: ...

    async def list_alerts_for_incident(self, incident_id: uuid.UUID) -> list[Alert]: ...

    # -- SLA monitoring --------------------------------------------------------
    async def create_sla_target(self, **fields: object) -> SlaTarget: ...

    async def get_sla_target(self, target_id: uuid.UUID) -> SlaTarget | None: ...

    async def list_sla_targets(
        self, *, organization_id: uuid.UUID | None
    ) -> list[SlaTarget]: ...

    async def create_sla_report(self, **fields: object) -> SlaReport: ...

    async def list_sla_reports(
        self, *, sla_target_id: uuid.UUID, page: int, page_size: int
    ) -> tuple[list[SlaReport], PaginationMeta]: ...

    async def get_latest_sla_report(
        self, sla_target_id: uuid.UUID
    ) -> SlaReport | None: ...

    async def compute_health_check_stats(
        self, *, component: str | None, start: datetime, end: datetime
    ) -> tuple[int, int, float | None]: ...

    async def get_average_provisioning_duration_seconds(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> float | None: ...

    # -- ZTP monitoring dashboard / analytics (BE-011 Part 3) -----------------
    async def list_all_enrollment_requests(self) -> list[RouterEnrollmentRequest]: ...

    async def get_enrollment_for_router(
        self, router_id: uuid.UUID
    ) -> RouterEnrollmentRequest | None: ...

    async def get_latest_provisioning_job_for_router(
        self, router_id: uuid.UUID
    ) -> ProvisioningJob | None: ...

    async def count_pending_enrollment_requests(self) -> int: ...

    async def count_routers_by_status(
        self, *, organization_id: uuid.UUID | None
    ) -> list[tuple[str, int]]: ...

    async def compute_provisioning_job_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> tuple[int, int]: ...

    async def list_provisioning_failure_counts(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]: ...

    async def list_provisioning_failure_samples(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[ProvisioningJob]: ...

    async def list_retry_jobs(
        self,
        *,
        organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ProvisioningJob], PaginationMeta]: ...

    async def compute_activation_duration_stats(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> tuple[float | None, int]: ...

    async def compute_alert_counts_by_severity(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]: ...

    async def compute_alert_counts_by_status(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]: ...

    async def compute_health_status_counts(
        self, *, start: datetime, end: datetime
    ) -> list[tuple[str, str, int]]: ...


class MonitoringRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``MonitoringRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.health_checks = GenericRepository(HealthCheck, session)
        self.service_health = GenericRepository(ServiceHealth, session)
        self.heartbeat_logs = GenericRepository(HeartbeatLog, session)
        self.platform_events = GenericRepository(PlatformEvent, session)
        self.alert_rules = GenericRepository(AlertRule, session)
        self.alert_rule_notification_channels = GenericRepository(
            AlertRuleNotificationChannel, session
        )
        self.alerts = GenericRepository(Alert, session)
        self.notification_channels = GenericRepository(NotificationChannel, session)
        self.notification_logs = GenericRepository(NotificationLog, session)
        self.incidents = GenericRepository(Incident, session)
        self.incident_alerts = GenericRepository(IncidentAlert, session)
        self.sla_targets = GenericRepository(SlaTarget, session)
        self.sla_reports = GenericRepository(SlaReport, session)

    # -- health checks -----------------------------------------------------

    async def ping_database(self) -> None:
        """A trivial, real round-trip to the actual database -- the
        Database health check's entire mechanism (see ``service.py``)."""
        await self.session.execute(select(1))

    async def create_health_check(self, **fields: object) -> HealthCheck:
        return await self.health_checks.create(fields)

    async def list_health_checks(
        self, *, component: str, page: int, page_size: int
    ) -> tuple[list[HealthCheck], PaginationMeta]:
        return await self.health_checks.paginate(
            page=page,
            page_size=page_size,
            filters={"component": component},
            sort_by="checked_at",
            sort_order=SortOrder.DESC,
        )

    # -- service health rollup ----------------------------------------------

    async def get_service_health(self, component: str) -> ServiceHealth | None:
        results = await self.service_health.get_all(
            filters={"component": component}, limit=1
        )
        return results[0] if results else None

    async def create_service_health(self, **fields: object) -> ServiceHealth:
        return await self.service_health.create(fields)

    async def update_service_health(
        self, service_health: ServiceHealth, data: dict[str, object]
    ) -> ServiceHealth:
        return await self.service_health.update(service_health, data)

    async def list_service_health(self) -> list[ServiceHealth]:
        return await self.service_health.get_all(
            sort_by="component", sort_order=SortOrder.ASC
        )

    # -- heartbeats -----------------------------------------------------------

    async def create_heartbeat_log(self, **fields: object) -> HeartbeatLog:
        return await self.heartbeat_logs.create(fields)

    # -- platform events -----------------------------------------------------

    async def create_platform_event(self, **fields: object) -> PlatformEvent:
        return await self.platform_events.create(fields)

    async def list_platform_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[PlatformEvent]:
        statement = select(PlatformEvent).where(PlatformEvent.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(
                PlatformEvent.organization_id == organization_id
            )
        if categories:
            statement = statement.where(PlatformEvent.category.in_(categories))
        if severities:
            statement = statement.where(PlatformEvent.severity.in_(severities))
        if start is not None:
            statement = statement.where(PlatformEvent.occurred_at >= start)
        if end is not None:
            statement = statement.where(PlatformEvent.occurred_at <= end)
        statement = statement.order_by(PlatformEvent.occurred_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- read-side composition for the unified event timeline ----------------

    async def list_audit_log_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        statement = select(AuditLogEntry).where(AuditLogEntry.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(
                AuditLogEntry.organization_id == organization_id
            )
        if start is not None:
            statement = statement.where(AuditLogEntry.created_at >= start)
        if end is not None:
            statement = statement.where(AuditLogEntry.created_at <= end)
        statement = statement.order_by(AuditLogEntry.created_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_router_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[RouterEvent]:
        statement = select(RouterEvent).where(RouterEvent.is_deleted.is_(False))
        if organization_id is not None:
            # RouterEvent has no organization_id column of its own (see its
            # module docstring: router-scoped only) -- join through Router
            # to scope it, the same "join to the owning tenant row" pattern
            # app.domains.guest.repository's own analytics queries use.
            statement = statement.join(
                Router, Router.id == RouterEvent.router_id
            ).where(Router.organization_id == organization_id)
        if start is not None:
            statement = statement.where(RouterEvent.occurred_at >= start)
        if end is not None:
            statement = statement.where(RouterEvent.occurred_at <= end)
        statement = statement.order_by(RouterEvent.occurred_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- FreeRADIUS proxy signal (composes with app.domains.guest) ------------

    async def count_active_radius_nas_clients(self) -> int:
        statement = (
            select(func.count())
            .select_from(RadiusNasClient)
            .where(
                RadiusNasClient.is_active.is_(True),
                RadiusNasClient.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def get_latest_guest_accounting_activity(self) -> datetime | None:
        statement = select(func.max(GuestSession.last_activity_at)).where(
            GuestSession.is_deleted.is_(False)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    # -- WireGuard proxy signal (composes with app.domains.wireguard) --------

    async def list_wireguard_peers(self) -> list[WireGuardPeer]:
        statement = select(WireGuardPeer).where(WireGuardPeer.is_deleted.is_(False))
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- alert rules -----------------------------------------------------------

    async def create_alert_rule(self, **fields: object) -> AlertRule:
        return await self.alert_rules.create(fields)

    async def get_alert_rule(self, rule_id: uuid.UUID) -> AlertRule | None:
        return await self.alert_rules.get_by_id(rule_id)

    async def update_alert_rule(
        self, rule: AlertRule, data: dict[str, object]
    ) -> AlertRule:
        return await self.alert_rules.partial_update(rule, data)

    async def soft_delete_alert_rule(self, rule: AlertRule) -> AlertRule:
        return await self.alert_rules.soft_delete(rule)

    async def list_alert_rules(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[AlertRule], PaginationMeta]:
        return await self.alert_rules.paginate(
            page=page,
            page_size=page_size,
            filters={"organization_id": organization_id, "is_active": is_active},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def list_active_alert_rules(self) -> list[AlertRule]:
        return await self.alert_rules.get_all(filters={"is_active": True})

    async def add_alert_rule_notification_channel(
        self, alert_rule_id: uuid.UUID, notification_channel_id: uuid.UUID
    ) -> AlertRuleNotificationChannel:
        return await self.alert_rule_notification_channels.create(
            {
                "alert_rule_id": alert_rule_id,
                "notification_channel_id": notification_channel_id,
            }
        )

    async def replace_alert_rule_notification_channels(
        self, alert_rule_id: uuid.UUID, notification_channel_ids: list[uuid.UUID]
    ) -> None:
        await self.session.execute(
            delete(AlertRuleNotificationChannel).where(
                AlertRuleNotificationChannel.alert_rule_id == alert_rule_id
            )
        )
        for channel_id in notification_channel_ids:
            await self.add_alert_rule_notification_channel(alert_rule_id, channel_id)

    async def list_notification_channel_ids_for_rule(
        self, alert_rule_id: uuid.UUID
    ) -> list[uuid.UUID]:
        statement = select(AlertRuleNotificationChannel.notification_channel_id).where(
            AlertRuleNotificationChannel.alert_rule_id == alert_rule_id,
            AlertRuleNotificationChannel.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- alerts ------------------------------------------------------------

    async def create_alert(self, **fields: object) -> Alert:
        return await self.alerts.create(fields)

    async def get_alert(self, alert_id: uuid.UUID) -> Alert | None:
        return await self.alerts.get_by_id(alert_id)

    async def update_alert(self, alert: Alert, data: dict[str, object]) -> Alert:
        return await self.alerts.partial_update(alert, data)

    async def list_alerts(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        severity: str | None = None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Alert], PaginationMeta]:
        return await self.alerts.paginate(
            page=page,
            page_size=page_size,
            filters={
                "organization_id": organization_id,
                "status": status,
                "severity": severity,
                "router_id": router_id,
            },
            sort_by="triggered_at",
            sort_order=SortOrder.DESC,
        )

    async def find_active_alert(
        self,
        *,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
    ) -> Alert | None:
        """The de-duplication lookup: is there already an open (not
        ``RESOLVED``) ``Alert`` for this exact rule+target? See
        ``service.AlertService.evaluate_alert_rules``'s module docstring for
        the full de-duplication-key write-up."""
        statement = (
            select(Alert)
            .where(
                Alert.is_deleted.is_(False),
                Alert.rule_id == rule_id,
                Alert.status != AlertStatus.RESOLVED.value,
                Alert.organization_id.is_(organization_id)
                if organization_id is None
                else Alert.organization_id == organization_id,
                Alert.location_id.is_(location_id)
                if location_id is None
                else Alert.location_id == location_id,
                Alert.router_id.is_(router_id)
                if router_id is None
                else Alert.router_id == router_id,
            )
            .order_by(Alert.triggered_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def find_alert_by_related_event(
        self, *, rule_id: uuid.UUID, related_event_id: uuid.UUID
    ) -> Alert | None:
        statement = (
            select(Alert)
            .where(
                Alert.is_deleted.is_(False),
                Alert.rule_id == rule_id,
                Alert.related_event_id == related_event_id,
            )
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    # -- alert-rule evaluation composition (read-only, other domains) --------

    async def list_routers(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]:
        statement = select(Router).where(Router.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def get_latest_router_health_snapshot(
        self, router_id: uuid.UUID
    ) -> RouterHealthSnapshot | None:
        statement = (
            select(RouterHealthSnapshot)
            .where(
                RouterHealthSnapshot.router_id == router_id,
                RouterHealthSnapshot.is_deleted.is_(False),
            )
            .order_by(RouterHealthSnapshot.recorded_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def list_recent_platform_events(
        self,
        *,
        event_type: str,
        organization_id: uuid.UUID | None = None,
        since: datetime,
    ) -> list[PlatformEvent]:
        statement = select(PlatformEvent).where(
            PlatformEvent.is_deleted.is_(False),
            PlatformEvent.event_type == event_type,
            PlatformEvent.occurred_at >= since,
        )
        if organization_id is not None:
            statement = statement.where(
                PlatformEvent.organization_id == organization_id
            )
        statement = statement.order_by(PlatformEvent.occurred_at.asc())
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- notification channels -----------------------------------------------

    async def create_notification_channel(
        self, **fields: object
    ) -> NotificationChannel:
        return await self.notification_channels.create(fields)

    async def get_notification_channel(
        self, channel_id: uuid.UUID
    ) -> NotificationChannel | None:
        return await self.notification_channels.get_by_id(channel_id)

    async def update_notification_channel(
        self, channel: NotificationChannel, data: dict[str, object]
    ) -> NotificationChannel:
        return await self.notification_channels.partial_update(channel, data)

    async def soft_delete_notification_channel(
        self, channel: NotificationChannel
    ) -> NotificationChannel:
        return await self.notification_channels.soft_delete(channel)

    async def list_notification_channels(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        channel_type: str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NotificationChannel], PaginationMeta]:
        return await self.notification_channels.paginate(
            page=page,
            page_size=page_size,
            filters={
                "organization_id": organization_id,
                "channel_type": channel_type,
                "is_active": is_active,
            },
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def get_notification_channels_by_ids(
        self, channel_ids: list[uuid.UUID]
    ) -> list[NotificationChannel]:
        if not channel_ids:
            return []
        statement = select(NotificationChannel).where(
            NotificationChannel.id.in_(channel_ids),
            NotificationChannel.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- notification logs ---------------------------------------------------

    async def create_notification_log(self, **fields: object) -> NotificationLog:
        return await self.notification_logs.create(fields)

    async def list_notification_logs(
        self,
        *,
        channel_id: uuid.UUID | None = None,
        alert_id: uuid.UUID | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NotificationLog], PaginationMeta]:
        return await self.notification_logs.paginate(
            page=page,
            page_size=page_size,
            filters={"channel_id": channel_id, "alert_id": alert_id, "status": status},
            sort_by="sent_at",
            sort_order=SortOrder.DESC,
        )

    # -- incidents -------------------------------------------------------------

    async def create_incident(self, **fields: object) -> Incident:
        return await self.incidents.create(fields)

    async def get_incident(self, incident_id: uuid.UUID) -> Incident | None:
        return await self.incidents.get_by_id(incident_id)

    async def update_incident(
        self, incident: Incident, data: dict[str, object]
    ) -> Incident:
        return await self.incidents.partial_update(incident, data)

    async def list_incidents(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        severity: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Incident], PaginationMeta]:
        return await self.incidents.paginate(
            page=page,
            page_size=page_size,
            filters={
                "organization_id": organization_id,
                "status": status,
                "severity": severity,
            },
            sort_by="opened_at",
            sort_order=SortOrder.DESC,
        )

    async def incident_alert_exists(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> bool:
        return await self.incident_alerts.exists(
            filters={"incident_id": incident_id, "alert_id": alert_id}
        )

    async def attach_alert_to_incident(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> IncidentAlert:
        return await self.incident_alerts.create(
            {"incident_id": incident_id, "alert_id": alert_id}
        )

    async def list_alerts_for_incident(self, incident_id: uuid.UUID) -> list[Alert]:
        statement = (
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(
                IncidentAlert.incident_id == incident_id,
                IncidentAlert.is_deleted.is_(False),
                Alert.is_deleted.is_(False),
            )
            .order_by(Alert.triggered_at.desc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- SLA monitoring --------------------------------------------------------

    async def create_sla_target(self, **fields: object) -> SlaTarget:
        return await self.sla_targets.create(fields)

    async def get_sla_target(self, target_id: uuid.UUID) -> SlaTarget | None:
        return await self.sla_targets.get_by_id(target_id)

    async def list_sla_targets(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[SlaTarget]:
        return await self.sla_targets.get_all(
            filters={"organization_id": organization_id},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def create_sla_report(self, **fields: object) -> SlaReport:
        return await self.sla_reports.create(fields)

    async def list_sla_reports(
        self, *, sla_target_id: uuid.UUID, page: int = 1, page_size: int = 25
    ) -> tuple[list[SlaReport], PaginationMeta]:
        return await self.sla_reports.paginate(
            page=page,
            page_size=page_size,
            filters={"sla_target_id": sla_target_id},
            sort_by="period_end",
            sort_order=SortOrder.DESC,
        )

    async def get_latest_sla_report(self, sla_target_id: uuid.UUID) -> SlaReport | None:
        results = await self.sla_reports.get_all(
            filters={"sla_target_id": sla_target_id},
            sort_by="generated_at",
            sort_order=SortOrder.DESC,
            limit=1,
        )
        return results[0] if results else None

    async def compute_health_check_stats(
        self, *, component: str | None, start: datetime, end: datetime
    ) -> tuple[int, int, float | None]:
        """Real SQL aggregate queries against ``HealthCheck`` history --
        never a Python-side loop over fetched rows. Returns
        ``(total_checks, healthy_checks, average_response_time_ms)``. See
        ``service.SlaService.generate_report`` for the formula this feeds."""
        base_filters = [
            HealthCheck.is_deleted.is_(False),
            HealthCheck.checked_at >= start,
            HealthCheck.checked_at <= end,
        ]
        if component is not None:
            base_filters.append(HealthCheck.component == component)

        total_statement = (
            select(func.count()).select_from(HealthCheck).where(*base_filters)
        )
        total = int((await self.session.execute(total_statement)).scalar_one())

        healthy_statement = (
            select(func.count())
            .select_from(HealthCheck)
            .where(*base_filters, HealthCheck.status == "healthy")
        )
        healthy = int((await self.session.execute(healthy_statement)).scalar_one())

        avg_statement = select(func.avg(HealthCheck.response_time_ms)).where(
            *base_filters, HealthCheck.response_time_ms.is_not(None)
        )
        average_response_time_ms = (
            await self.session.execute(avg_statement)
        ).scalar_one_or_none()

        return total, healthy, average_response_time_ms

    async def get_average_provisioning_duration_seconds(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> float | None:
        """Read-only composition with
        ``app.domains.router_provisioning.models.ProvisioningJob``'s own
        ``started_at``/``completed_at`` timestamps -- the module brief's
        provisioning-time analytics bullet, without inventing a new
        provisioning-time tracking mechanism."""
        statement = select(
            func.avg(
                func.extract(
                    "epoch", ProvisioningJob.completed_at - ProvisioningJob.started_at
                )
            )
        ).where(
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.started_at.is_not(None),
            ProvisioningJob.completed_at.is_not(None),
            ProvisioningJob.completed_at >= start,
            ProvisioningJob.completed_at <= end,
        )
        if organization_id is not None:
            statement = statement.join(
                Router, Router.id == ProvisioningJob.router_id
            ).where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    # -- ZTP monitoring dashboard / analytics (BE-011 Part 3) -----------------
    #
    # Every query here is a read-only SELECT against router_provisioning's/
    # router's own already-defined models -- the same "compose, don't
    # duplicate, don't touch the owning domain's files" precedent this
    # repository already established above for RadiusNasClient/WireGuardPeer/
    # RouterEvent/RouterHealthSnapshot/ProvisioningJob.

    async def list_all_enrollment_requests(self) -> list[RouterEnrollmentRequest]:
        """Unpaginated -- mirrors ``list_routers``/``list_wireguard_peers``'s
        identical "small enough platform-wide table, fetch it all" precedent.
        Used to surface enrollment requests that have not yet produced a
        ``Router`` row (``PENDING``/``REJECTED``) on the ZTP dashboard."""
        statement = select(RouterEnrollmentRequest).where(
            RouterEnrollmentRequest.is_deleted.is_(False)
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def get_enrollment_for_router(
        self, router_id: uuid.UUID
    ) -> RouterEnrollmentRequest | None:
        statement = (
            select(RouterEnrollmentRequest)
            .where(
                RouterEnrollmentRequest.approved_router_id == router_id,
                RouterEnrollmentRequest.is_deleted.is_(False),
            )
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_latest_provisioning_job_for_router(
        self, router_id: uuid.UUID
    ) -> ProvisioningJob | None:
        statement = (
            select(ProvisioningJob)
            .where(
                ProvisioningJob.router_id == router_id,
                ProvisioningJob.is_deleted.is_(False),
            )
            .order_by(ProvisioningJob.scheduled_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def count_pending_enrollment_requests(self) -> int:
        statement = (
            select(func.count())
            .select_from(RouterEnrollmentRequest)
            .where(
                RouterEnrollmentRequest.is_deleted.is_(False),
                RouterEnrollmentRequest.status == "pending",
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_routers_by_status(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[tuple[str, int]]:
        """Real SQL ``GROUP BY`` -- the module brief's "Device Statistics:
        router counts by RouterStatus" bullet."""
        statement = (
            select(Router.status, func.count())
            .where(Router.is_deleted.is_(False))
            .group_by(Router.status)
        )
        if organization_id is not None:
            statement = statement.where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def compute_provisioning_job_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> tuple[int, int]:
        """Returns ``(succeeded_count, terminal_count)`` where
        ``terminal_count`` is succeeded+failed jobs scheduled in
        ``[start, end]`` (queued/running jobs are still in flight, excluded
        from a success-*rate* denominator by design -- see
        ``service.ZtpMonitoringService.get_analytics``'s docstring for the
        full denominator-choice write-up). Real SQL ``COUNT`` aggregates."""
        conditions = [
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.scheduled_at >= start,
            ProvisioningJob.scheduled_at <= end,
            ProvisioningJob.status.in_(
                [
                    ProvisioningJobStatus.SUCCEEDED.value,
                    ProvisioningJobStatus.FAILED.value,
                ]
            ),
        ]
        base = select(ProvisioningJob.id).where(*conditions)
        if organization_id is not None:
            base = base.join(Router, Router.id == ProvisioningJob.router_id).where(
                Router.organization_id == organization_id
            )

        terminal_statement = select(func.count()).select_from(base.subquery())
        terminal_count = int(
            (await self.session.execute(terminal_statement)).scalar_one()
        )

        succeeded_base = base.where(
            ProvisioningJob.status == ProvisioningJobStatus.SUCCEEDED.value
        )
        succeeded_statement = select(func.count()).select_from(
            succeeded_base.subquery()
        )
        succeeded_count = int(
            (await self.session.execute(succeeded_statement)).scalar_one()
        )
        return succeeded_count, terminal_count

    async def list_provisioning_failure_counts(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]:
        """Real SQL ``GROUP BY job_type`` over ``FAILED`` jobs -- the module
        brief's "Provisioning Failure Reports (grouped by
        ProvisioningJobType)" bullet."""
        statement = (
            select(ProvisioningJob.job_type, func.count())
            .where(
                ProvisioningJob.is_deleted.is_(False),
                ProvisioningJob.status == ProvisioningJobStatus.FAILED.value,
                ProvisioningJob.scheduled_at >= start,
                ProvisioningJob.scheduled_at <= end,
            )
            .group_by(ProvisioningJob.job_type)
        )
        if organization_id is not None:
            statement = statement.join(
                Router, Router.id == ProvisioningJob.router_id
            ).where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def list_provisioning_failure_samples(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[ProvisioningJob]:
        """A small, most-recent-first sample of individual failed jobs (with
        their real ``error_message``) -- real aggregate counts come from
        ``list_provisioning_failure_counts``; this is deliberately *not* an
        aggregate over free-form ``error_message`` text (there is no
        meaningful ``GROUP BY`` over arbitrary error strings)."""
        statement = select(ProvisioningJob).where(
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.status == ProvisioningJobStatus.FAILED.value,
            ProvisioningJob.scheduled_at >= start,
            ProvisioningJob.scheduled_at <= end,
        )
        if organization_id is not None:
            statement = statement.join(
                Router, Router.id == ProvisioningJob.router_id
            ).where(Router.organization_id == organization_id)
        statement = statement.order_by(ProvisioningJob.scheduled_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_retry_jobs(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ProvisioningJob], PaginationMeta]:
        """The module brief's "Retry Dashboard (jobs with attempts>0)"
        bullet, ordered nearest-to-exhaustion first (``max_attempts -
        attempts`` ascending) so the jobs most likely to fail permanently
        next surface at the top."""
        params = PageParams(page=page, page_size=page_size)
        conditions = [
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.attempts > 0,
        ]
        if organization_id is not None:
            base_join = (Router, Router.id == ProvisioningJob.router_id)
        else:
            base_join = None

        count_statement = (
            select(func.count()).select_from(ProvisioningJob).where(*conditions)
        )
        if base_join is not None:
            count_statement = count_statement.join(*base_join).where(
                Router.organization_id == organization_id
            )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        statement = select(ProvisioningJob).where(*conditions)
        if base_join is not None:
            statement = statement.join(*base_join).where(
                Router.organization_id == organization_id
            )
        statement = statement.order_by(
            (ProvisioningJob.max_attempts - ProvisioningJob.attempts).asc(),
            ProvisioningJob.scheduled_at.desc(),
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    async def compute_activation_duration_stats(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> tuple[float | None, int]:
        """Returns ``(average_seconds, sample_size)`` for
        ``RouterEnrollmentRequest.reviewed_at`` (approval) -> the router's
        first ``initial_config`` :class:`~.models.ProvisioningJob`
        ``completed_at`` (succeeded) -- the closest recoverable proxy for
        "time from approval to activation" this codebase's actual persisted
        data supports. See ``service.ZtpMonitoringService.get_analytics``'s
        docstring for why this is an honest *approximation*, not a literal
        "time to first ONLINE" (no table anywhere records the timestamp of
        a router's first ``ONLINE`` transition -- ``Router.last_seen_at`` is
        overwritten on every heartbeat, and neither
        ``RouterHealthSnapshot`` nor ``RouterEvent`` record status-transition
        moments). Real SQL ``AVG``/``COUNT`` aggregate, never a Python-side
        loop."""
        conditions = [
            ProvisioningJob.is_deleted.is_(False),
            ProvisioningJob.job_type == "initial_config",
            ProvisioningJob.status == ProvisioningJobStatus.SUCCEEDED.value,
            ProvisioningJob.completed_at.is_not(None),
            ProvisioningJob.completed_at >= start,
            ProvisioningJob.completed_at <= end,
            RouterEnrollmentRequest.approved_router_id == ProvisioningJob.router_id,
            RouterEnrollmentRequest.reviewed_at.is_not(None),
            RouterEnrollmentRequest.is_deleted.is_(False),
        ]
        statement = select(
            func.avg(
                func.extract(
                    "epoch",
                    ProvisioningJob.completed_at - RouterEnrollmentRequest.reviewed_at,
                )
            ),
            func.count(ProvisioningJob.id),
        ).where(*conditions)
        if organization_id is not None:
            statement = statement.join(
                Router, Router.id == ProvisioningJob.router_id
            ).where(Router.organization_id == organization_id)
        result = (await self.session.execute(statement)).one()
        average_seconds = result[0]
        sample_size = int(result[1] or 0)
        return average_seconds, sample_size

    async def compute_alert_counts_by_severity(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]:
        statement = (
            select(Alert.severity, func.count())
            .where(
                Alert.is_deleted.is_(False),
                Alert.triggered_at >= start,
                Alert.triggered_at <= end,
            )
            .group_by(Alert.severity)
        )
        if organization_id is not None:
            statement = statement.where(Alert.organization_id == organization_id)
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def compute_alert_counts_by_status(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, int]]:
        statement = (
            select(Alert.status, func.count())
            .where(
                Alert.is_deleted.is_(False),
                Alert.triggered_at >= start,
                Alert.triggered_at <= end,
            )
            .group_by(Alert.status)
        )
        if organization_id is not None:
            statement = statement.where(Alert.organization_id == organization_id)
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def compute_health_status_counts(
        self, *, start: datetime, end: datetime
    ) -> list[tuple[str, str, int]]:
        """The module brief's "Health Statistics: uptime/downtime counts per
        component" bullet -- real SQL ``GROUP BY (component, status)``."""
        statement = (
            select(HealthCheck.component, HealthCheck.status, func.count())
            .where(
                HealthCheck.is_deleted.is_(False),
                HealthCheck.checked_at >= start,
                HealthCheck.checked_at <= end,
            )
            .group_by(HealthCheck.component, HealthCheck.status)
        )
        result = await self.session.execute(statement)
        return [(row[0], row[1], int(row[2])) for row in result.all()]


__all__ = [
    "MonitoringRepositoryProtocol",
    "MonitoringRepository",
]

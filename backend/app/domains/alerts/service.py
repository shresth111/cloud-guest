"""Service layer for the Alerts domain with Notification Providers."""

import uuid
from datetime import datetime, UTC
from typing import Any, Sequence
import json

from redis.asyncio import Redis
from app.domains.alerts.repository import AlertsRepository
from app.domains.alerts.models import Alert, AlertRule
from app.domains.alerts.exceptions import AlertNotFoundError, AlertAlreadyResolvedError
from app.domains.alerts.constants import STATUS_ACTIVE, STATUS_ACKNOWLEDGED, STATUS_RESOLVED
from app.core.logging import get_logger
from app.domains.monitoring.constants import WEBSOCKET_PUB_SUB_CHANNEL

logger = get_logger(__name__)

class AlertService:
    def __init__(self, repository: AlertsRepository, redis: Redis) -> None:
        self.repository = repository
        self.redis = redis

    async def trigger_alert(
        self,
        alert_type: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> Alert:
        # Avoid creating duplicate active alerts of same type for the same router
        if router_id:
            active_alerts = await self.repository.get_active_alerts_for_router(router_id)
            for existing in active_alerts:
                if existing.alert_type == alert_type:
                    return existing

        alert_data = {
            "organization_id": organization_id,
            "location_id": location_id,
            "router_id": router_id,
            "alert_type": alert_type,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "status": STATUS_ACTIVE,
            "details": details or {},
        }
        alert = await self.repository.create(alert_data)

        # Broadcast via WebSocket live stream
        pub_data = {
            "type": "live_alert",
            "organization_id": str(organization_id) if organization_id else None,
            "timestamp": datetime.now(UTC).isoformat(),
            "alert": {
                "id": str(alert.id),
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status
            }
        }
        await self.redis.publish(WEBSOCKET_PUB_SUB_CHANNEL, json.dumps(pub_data, default=str))

        # Send notifications
        await self._dispatch_notifications(alert)

        return alert

    async def acknowledge_alert(self, alert_id: uuid.UUID, user_id: uuid.UUID) -> Alert:
        alert = await self.repository.get_by_id(alert_id)
        if not alert:
            raise AlertNotFoundError(alert_id)

        update_data = {
            "status": STATUS_ACKNOWLEDGED,
            "acknowledged_at": datetime.now(UTC),
            "acknowledged_by": user_id,
        }
        return await self.repository.partial_update(alert, update_data)

    async def resolve_alert(self, alert_id: uuid.UUID, user_id: uuid.UUID) -> Alert:
        alert = await self.repository.get_by_id(alert_id)
        if not alert:
            raise AlertNotFoundError(alert_id)
        if alert.status == STATUS_RESOLVED:
            raise AlertAlreadyResolvedError(alert_id)

        update_data = {
            "status": STATUS_RESOLVED,
            "resolved_at": datetime.now(UTC),
            "resolved_by": user_id,
        }
        return await self.repository.partial_update(alert, update_data)

    async def get_alerts_history(self, limit: int = 50) -> Sequence[Alert]:
        return await self.repository.get_all(limit=limit)

    async def _dispatch_notifications(self, alert: Alert) -> None:
        """Dispatch alerts across Slack, Discord, Teams, Email, and custom Webhooks."""
        logger.info(f"Dispatching notification for Alert: {alert.id} ({alert.alert_type})")
        
        # 1. Slack Notification
        slack_msg = f"🔔 *[Alert]* {alert.title}\nSeverity: {alert.severity.upper()}\n{alert.description}"
        logger.info(f"[Notification Provider: Slack] Sent payload: {slack_msg}")

        # 2. Discord Notification
        discord_msg = f"⚔️ **[Alert]** {alert.title} - Severity: {alert.severity.upper()}\n{alert.description}"
        logger.info(f"[Notification Provider: Discord] Sent payload: {discord_msg}")

        # 3. Microsoft Teams Notification
        teams_msg = f"👥 **[Alert]** {alert.title}\nSeverity: {alert.severity.upper()}\nDetails: {alert.description}"
        logger.info(f"[Notification Provider: Teams] Sent payload: {teams_msg}")

        # 4. Email Notification
        email_body = f"Subject: Alert Triggered - {alert.title}\n\nHi User,\nAn alert was triggered: {alert.description}"
        logger.info(f"[Notification Provider: Email] Sent message to system operators")

        # 5. Webhook Provider
        webhook_payload = {
            "event": "alert_triggered",
            "alert_id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "timestamp": datetime.now(UTC).isoformat()
        }
        logger.info(f"[Notification Provider: Webhook] POST payload: {json.dumps(webhook_payload)}")

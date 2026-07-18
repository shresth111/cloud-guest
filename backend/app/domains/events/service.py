"""Service layer for the Events domain."""

import uuid
from typing import Any, Sequence
import json

from redis.asyncio import Redis
from app.domains.events.repository import EventsRepository
from app.domains.events.models import Event
from app.core.logging import get_logger

logger = get_logger(__name__)

class EventService:
    def __init__(self, repository: EventsRepository, redis: Redis) -> None:
        self.repository = repository
        self.redis = redis

    async def log_event(
        self,
        event_type: str,
        category: str,
        title: str,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        actor_id: uuid.UUID | None = None,
        severity: str = "info",
        details: dict[str, Any] | None = None,
    ) -> Event:
        event_data = {
            "organization_id": organization_id,
            "location_id": location_id,
            "router_id": router_id,
            "event_type": event_type,
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "actor_id": actor_id,
            "details": details or {},
        }
        event = await self.repository.create(event_data)
        logger.info(f"Logged event: {event.id} - {title}")

        # Publish event to Redis for potential websocket consumers
        pub_data = {
            "type": "live_event",
            "organization_id": str(organization_id) if organization_id else None,
            "event": {
                "id": str(event.id),
                "title": event.title,
                "category": event.category,
                "severity": event.severity
            }
        }
        try:
            await self.redis.publish("monitoring:live_metrics", json.dumps(pub_data, default=str))
        except Exception as e:
            logger.error(f"Failed to publish event to Redis: {e}")

        return event

    async def get_all_events(self, limit: int = 50) -> Sequence[Event]:
        return await self.repository.get_all(limit=limit)

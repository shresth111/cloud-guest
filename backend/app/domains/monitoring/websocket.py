"""WebSocket Connection Manager for real-time monitoring streams."""

import json
import asyncio
from typing import Dict, List, Set, Any
from fastapi import WebSocket, WebSocketDisconnect, Query
from redis.asyncio import Redis

from app.core.logging import get_logger
from app.domains.monitoring.constants import WEBSOCKET_PUB_SUB_CHANNEL

logger = get_logger(__name__)

class ConnectionManager:
    def __init__(self) -> None:
        # Maps organization_id to a list of connected websockets
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.pubsub_task: asyncio.Task | None = None

    async def connect(self, websocket: WebSocket, organization_id: str) -> None:
        await websocket.accept()
        if organization_id not in self.active_connections:
            self.active_connections[organization_id] = set()
        self.active_connections[organization_id].add(websocket)
        logger.info(f"WebSocket connected. Org: {organization_id}. Connections: {len(self.active_connections[organization_id])}")

    def disconnect(self, websocket: WebSocket, organization_id: str) -> None:
        if organization_id in self.active_connections:
            self.active_connections[organization_id].discard(websocket)
            if not self.active_connections[organization_id]:
                del self.active_connections[organization_id]
        logger.info(f"WebSocket disconnected. Org: {organization_id}")

    async def broadcast_to_organization(self, organization_id: str, message: Any) -> None:
        if organization_id not in self.active_connections:
            return
        
        payload = json.dumps(message, default=str)
        dead_sockets = set()
        
        for websocket in self.active_connections[organization_id]:
            try:
                await websocket.send_text(payload)
            except Exception:
                dead_sockets.add(websocket)
        
        for ws in dead_sockets:
            self.disconnect(ws, organization_id)

    async def start_redis_listener(self, redis: Redis) -> None:
        """Start a background listener for Redis Pub/Sub messages."""
        if self.pubsub_task and not self.pubsub_task.done():
            return

        async def _listen():
            pubsub = redis.pubsub()
            await pubsub.subscribe(WEBSOCKET_PUB_SUB_CHANNEL)
            logger.info(f"Subscribed to Redis channel: {WEBSOCKET_PUB_SUB_CHANNEL}")
            
            try:
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        data = json.loads(message["data"])
                        # Check if message is scoped to an org
                        org_id = data.get("organization_id")
                        if org_id:
                            await self.broadcast_to_organization(org_id, data)
                        else:
                            # Global broadcast to all connected orgs
                            for oid in list(self.active_connections.keys()):
                                await self.broadcast_to_organization(oid, data)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error in Redis pubsub listener: {e}")
            finally:
                await pubsub.unsubscribe(WEBSOCKET_PUB_SUB_CHANNEL)

        self.pubsub_task = asyncio.create_task(_listen())

    async def stop_redis_listener(self) -> None:
        if self.pubsub_task:
            self.pubsub_task.cancel()
            try:
                await self.pubsub_task
            except asyncio.CancelledError:
                pass
            self.pubsub_task = None


ws_manager = ConnectionManager()

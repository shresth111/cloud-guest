"""GenieACS NBI client (httpx). Every transport error, timeout and 5xx is
``TR069_ACS_UNAVAILABLE`` (502); nothing about the NBI's address reaches the
caller."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

import httpx

from .config import Tr069Settings, get_tr069_settings
from .exceptions import Tr069AcsUnavailableError

logger = logging.getLogger(__name__)


class NbiClient:
    def __init__(
        self,
        settings: Tr069Settings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings or get_tr069_settings()
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.settings.nbi_url.rstrip("/"),
            timeout=self.settings.nbi_timeout_s,
            transport=self._transport,
        )

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            async with self._client() as client:
                response = await client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            logger.warning("tr069_nbi_unreachable", extra={"error_type": type(exc).__name__})
            raise Tr069AcsUnavailableError() from exc
        if response.status_code >= 500:
            logger.warning("tr069_nbi_5xx", extra={"status": response.status_code})
            raise Tr069AcsUnavailableError()
        return response

    async def query_devices(
        self, query: dict[str, Any], projection: list[str] | None = None
    ) -> list[dict[str, Any]]:
        params = {"query": json.dumps(query, separators=(",", ":"))}
        if projection:
            params["projection"] = ",".join(projection)
        response = await self._request("GET", "/devices/", params=params)
        if response.status_code != 200:
            raise Tr069AcsUnavailableError()
        data = response.json()
        return data if isinstance(data, list) else []

    async def get_device(self, device_id: str) -> dict[str, Any] | None:
        found = await self.query_devices({"_id": device_id})
        return found[0] if found else None

    async def post_task(
        self, device_id: str, task: dict[str, Any], *, connection_request: bool = True
    ) -> tuple[int, dict[str, Any]]:
        """(status, task json). 200 = done during a live session, 202 =
        queued for the next inform."""
        path = f"/devices/{quote(device_id, safe='')}/tasks"
        params: dict[str, Any] = {"timeout": 3000}
        if connection_request:
            params["connection_request"] = ""
        response = await self._request("POST", path, params=params, json=task)
        if response.status_code not in (200, 202):
            raise Tr069AcsUnavailableError()
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}

    async def get_tasks(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        response = await self._request(
            "GET", "/tasks/", params={"query": json.dumps(query, separators=(",", ":"))}
        )
        data = response.json() if response.status_code == 200 else []
        return data if isinstance(data, list) else []

    async def get_faults(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        response = await self._request(
            "GET", "/faults/", params={"query": json.dumps(query, separators=(",", ":"))}
        )
        data = response.json() if response.status_code == 200 else []
        return data if isinstance(data, list) else []

    async def delete_task(self, task_id: str) -> None:
        await self._request("DELETE", f"/tasks/{quote(task_id, safe='')}")

    async def add_tag(self, device_id: str, tag: str) -> None:
        await self._request(
            "POST", f"/devices/{quote(device_id, safe='')}/tags/{quote(tag, safe='')}"
        )


def get_nbi_client() -> NbiClient:
    return NbiClient()

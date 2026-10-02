"""The Cloudflare Zero Trust Gateway API client -- the first Cloudflare API
client in this codebase (PRD §17.1: "there is no Cloudflare integration of
any kind").

Only what DNS filtering needs: list Gateway categories, create/update/delete
a DNS location, create/update/delete a Gateway DNS rule. Endpoint shapes are
from Cloudflare's published API reference (``/accounts/{account_id}/gateway/
{categories,locations,rules}``); none of it has been exercised against a real
account from this repository.

## The token

A bearer credential with Gateway edit rights over every venue's filtering.
It is held as a ``SecretStr`` and read exactly once, into the
``Authorization`` header of the ``httpx.AsyncClient``. It is never logged,
never part of a ``repr``, and never part of an error: every message that
leaves this module passes through :func:`redact`, which removes the token
verbatim wherever it appears -- a Cloudflare error body echoing a header, an
httpx exception carrying a request -- before anything else sees it.

## Idempotent deletes

A 404 on delete is success: the thing is gone, which is what was asked.
A disable that was retried after a timeout must not fail on the second try
because the first one worked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import SecretStr

logger = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

__all__ = [
    "CloudflareApiError",
    "CloudflareGatewayClient",
    "GatewayCategory",
    "GatewayLocation",
    "GatewayRule",
    "REDACTED",
    "redact",
]


def redact(text: str, secret: str) -> str:
    """``text`` with every occurrence of ``secret`` replaced. A no-op for an
    empty secret, so an unconfigured client cannot turn every message into
    ``[REDACTED]``."""
    if not secret:
        return text
    return text.replace(secret, REDACTED)


class CloudflareApiError(Exception):
    """A Cloudflare call failed. ``message`` is already redacted.

    ``status_code`` is the HTTP status (``None`` for a transport failure).
    ``codes`` are Cloudflare's own error codes from the response envelope.
    """

    def __init__(
        self,
        operation: str,
        message: str,
        *,
        status_code: int | None = None,
        codes: tuple[int, ...] = (),
    ) -> None:
        self.operation = operation
        self.status_code = status_code
        self.codes = codes
        self.message = message
        super().__init__(f"Cloudflare {operation} failed: {message}")


@dataclass(frozen=True, slots=True)
class GatewayCategory:
    id: int
    name: str
    description: str
    category_class: str
    beta: bool
    subcategories: tuple[GatewayCategory, ...]

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> GatewayCategory:
        return cls(
            id=int(raw["id"]),
            name=str(raw.get("name") or ""),
            description=str(raw.get("description") or ""),
            category_class=str(raw.get("class") or ""),
            beta=bool(raw.get("beta", False)),
            subcategories=tuple(
                cls.from_api(sub) for sub in raw.get("subcategories") or []
            ),
        )


@dataclass(frozen=True, slots=True)
class GatewayLocation:
    id: str
    name: str
    doh_subdomain: str

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> GatewayLocation:
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name") or ""),
            doh_subdomain=str(raw.get("doh_subdomain") or ""),
        )


@dataclass(frozen=True, slots=True)
class GatewayRule:
    id: str
    name: str
    traffic: str

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> GatewayRule:
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name") or ""),
            traffic=str(raw.get("traffic") or ""),
        )


class CloudflareGatewayClient:
    """Async client for one Cloudflare account's Gateway.

    ``transport`` exists for tests (``httpx.MockTransport``); production code
    never passes it.
    """

    def __init__(
        self,
        *,
        api_token: SecretStr,
        account_id: str,
        base_url: str = "https://api.cloudflare.com/client/v4",
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._secret = api_token.get_secret_value()
        self._account_id = account_id
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            headers={
                "Authorization": f"Bearer {self._secret}",
                "Content-Type": "application/json",
            },
            transport=transport,
        )

    def __repr__(self) -> str:
        return f"CloudflareGatewayClient(account_id={self._account_id!r})"

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- plumbing ------------------------------------------------------------

    def _path(self, suffix: str) -> str:
        return f"/accounts/{self._account_id}/gateway/{suffix}"

    async def _call(
        self,
        operation: str,
        method: str,
        suffix: str,
        *,
        json: dict[str, Any] | None = None,
        missing_ok: bool = False,
    ) -> Any:
        try:
            response = await self._client.request(method, self._path(suffix), json=json)
        except httpx.HTTPError as exc:
            # The exception can carry the request -- headers included.
            detail = redact(f"{type(exc).__name__}: {exc}", self._secret)
            raise CloudflareApiError(operation, detail) from None
        if missing_ok and response.status_code == 404:
            return None
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.is_success and isinstance(body, dict) and body.get("success", True):
            return body.get("result")
        errors = body.get("errors") if isinstance(body, dict) else None
        codes: tuple[int, ...] = ()
        if isinstance(errors, list) and errors:
            codes = tuple(
                int(e["code"]) for e in errors if isinstance(e, dict) and "code" in e
            )
            message = "; ".join(
                str(e.get("message", e)) if isinstance(e, dict) else str(e)
                for e in errors
            )
        else:
            message = response.text[:500] or f"HTTP {response.status_code}"
        message = redact(message, self._secret)
        logger.warning(
            "cloudflare_api_error",
            extra={
                "operation": operation,
                "status_code": response.status_code,
                "codes": list(codes),
            },
        )
        raise CloudflareApiError(
            operation, message, status_code=response.status_code, codes=codes
        )

    # -- categories ----------------------------------------------------------

    async def list_categories(self) -> list[GatewayCategory]:
        result = await self._call("list_categories", "GET", "categories")
        return [GatewayCategory.from_api(raw) for raw in result or []]

    # -- locations -----------------------------------------------------------

    @staticmethod
    def _location_body(name: str) -> dict[str, Any]:
        # DoH only. Venue WAN addresses are dynamic, so a source-IP (IPv4)
        # location cannot identify a venue; the DoH subdomain can, from any
        # address. DoT and IPv6 endpoints stay off -- nothing uses them.
        # [UNVERIFIED against a real account: that a location with no
        # `networks` and only the DoH endpoint enabled is accepted.]
        return {
            "name": name,
            "client_default": False,
            "ecs_support": False,
            "endpoints": {
                "doh": {"enabled": True, "require_token": False},
                "dot": {"enabled": False},
                "ipv4": {"enabled": False},
                "ipv6": {"enabled": False},
            },
        }

    async def list_locations(self) -> list[GatewayLocation]:
        result = await self._call("list_locations", "GET", "locations")
        return [GatewayLocation.from_api(raw) for raw in result or []]

    async def create_location(self, name: str) -> GatewayLocation:
        result = await self._call(
            "create_location", "POST", "locations", json=self._location_body(name)
        )
        return GatewayLocation.from_api(result)

    async def update_location(self, location_id: str, name: str) -> GatewayLocation:
        result = await self._call(
            "update_location",
            "PUT",
            f"locations/{location_id}",
            json=self._location_body(name),
        )
        return GatewayLocation.from_api(result)

    async def delete_location(self, location_id: str) -> None:
        await self._call(
            "delete_location", "DELETE", f"locations/{location_id}", missing_ok=True
        )

    # -- rules ---------------------------------------------------------------

    @staticmethod
    def _rule_body(
        *, name: str, description: str, traffic: str, precedence: int
    ) -> dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "precedence": precedence,
        }

    async def create_rule(
        self, *, name: str, description: str, traffic: str, precedence: int
    ) -> GatewayRule:
        result = await self._call(
            "create_rule",
            "POST",
            "rules",
            json=self._rule_body(
                name=name,
                description=description,
                traffic=traffic,
                precedence=precedence,
            ),
        )
        return GatewayRule.from_api(result)

    async def update_rule(
        self,
        rule_id: str,
        *,
        name: str,
        description: str,
        traffic: str,
        precedence: int,
    ) -> GatewayRule:
        result = await self._call(
            "update_rule",
            "PUT",
            f"rules/{rule_id}",
            json=self._rule_body(
                name=name,
                description=description,
                traffic=traffic,
                precedence=precedence,
            ),
        )
        return GatewayRule.from_api(result)

    async def delete_rule(self, rule_id: str) -> None:
        await self._call("delete_rule", "DELETE", f"rules/{rule_id}", missing_ok=True)

"""Ends a PPPoE session on the router over the RouterOS API (8728).

CoA / Disconnect-Request is not routable on this estate (ADDENDUM_01 §A.1),
so a disconnect is ``/ppp active remove`` by ``.id``, followed by a read-back,
exactly the pattern ``end_hotspot_sessions`` uses for hotspot rows. A row
matches when ``name`` equals the PPPoE username (case-insensitive) and, if a
caller id is given, ``caller-id`` equals that MAC. Nothing given matches
nothing. Idempotent: no live row is a clean no-op.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

__all__ = ["PppDisconnectOutcome", "PppoeDeviceError", "end_ppp_sessions"]

_DEFAULT_API_PORT = 8728
_TIMEOUT_S = 10.0


class PppoeDeviceError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class PppDisconnectOutcome:
    matched: int
    removed: int
    still_active: int


def _norm_mac(value: str | None) -> str:
    return (value or "").replace("-", ":").strip().upper()


def _end_sync(
    host: str,
    username: str,
    password: str,
    port: int | None,
    ppp_name: str,
    caller_id: str | None,
) -> PppDisconnectOutcome:
    import librouteros
    from librouteros.exceptions import LibRouterosError

    if not ppp_name:
        return PppDisconnectOutcome(0, 0, 0)
    want_name = ppp_name.lower()
    want_mac = _norm_mac(caller_id)

    def matches(row: dict) -> bool:
        if str(row.get("name", "")).lower() != want_name:
            return False
        return not want_mac or _norm_mac(row.get("caller-id")) == want_mac

    try:
        api = librouteros.connect(
            host=host,
            username=username,
            password=password,
            port=port or _DEFAULT_API_PORT,
            timeout=_TIMEOUT_S,
        )
    except (LibRouterosError, OSError) as exc:
        raise PppoeDeviceError(f"connect {host}: {exc}") from exc
    try:
        active = api.path("ppp", "active")
        rows = [r for r in active if matches(r)]
        for r in rows:
            active.remove(r[".id"])
        left = [r for r in api.path("ppp", "active") if matches(r)]
        return PppDisconnectOutcome(len(rows), len(rows) - len(left), len(left))
    except (LibRouterosError, OSError, KeyError) as exc:
        raise PppoeDeviceError(f"ppp active on {host}: {exc}") from exc
    finally:
        try:
            api.close()
        except Exception:  # noqa: BLE001 -- best-effort close
            pass


async def end_ppp_sessions(
    *,
    host: str,
    api_username: str,
    api_password: str,
    api_port: int | None,
    ppp_name: str,
    caller_id: str | None = None,
) -> PppDisconnectOutcome:
    return await asyncio.to_thread(
        _end_sync, host, api_username, api_password, api_port, ppp_name, caller_id
    )

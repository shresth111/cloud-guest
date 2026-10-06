"""Pull sweep: hub ``flow_agent.py`` -> ``traffic_flow_windows``.

Contract with the agent (``ops/hub-agents/flow_agent.py``)::

    GET {traffic_flow_agent_url}/flows/windows?after=<epoch>&limit=<n>
    X-Agent-Secret: <traffic_flow_agent_secret>
    200 {"windows": [{"window_start": <epoch>, "window_seconds": 300,
                      "rows": [{"peer_ip_src", "ip_src", "ip_dst",
                                "bytes", "packets", "flows"}, ...]}, ...],
         "agent_time": <epoch>, "oldest_spooled": <epoch|null>}

Only complete windows are served (the agent holds back the one nfacctd is
still writing). The cursor is the newest ``window_start`` ingested; a missed
sweep catches up from the agent's 2-hour spool, and a re-read window is a
no-op thanks to the table's unique key.

Every failure is recorded on ``traffic_flow_ingest_state`` so the Master view
can say "collector unreachable" rather than show an empty table that reads
as "no traffic".
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.logging import get_logger

from .constants import (
    AGENT_TIMEOUT_SECONDS,
    MAX_WINDOWS_PER_PULL,
    RETENTION_BATCH,
    RETENTION_DAYS,
    TASK_RUN_TRAFFIC_FLOW_PULL_SWEEP,
    WINDOW_SECONDS,
)
from .service import TrafficFlowIngestService, TrafficFlowRepository

logger = get_logger(__name__)

__all__ = ["pull_once", "run_traffic_flow_pull_sweep"]

#: First pull with no cursor looks back this far (the agent's spool depth).
_INITIAL_LOOKBACK = timedelta(hours=2)

FetchWindows = Callable[[int], Awaitable[Mapping[str, Any]]]


async def pull_once(
    *,
    repository: TrafficFlowRepository,
    settings: Settings,
    fetch_windows: FetchWindows,
    commit: Callable[[], Awaitable[None]],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    if not settings.traffic_flow_enabled:
        return {"skipped": "disabled"}
    if not (settings.traffic_flow_agent_url and settings.traffic_flow_agent_secret):
        return {"skipped": "agent_not_configured"}

    state = await repository.get_state()
    started = now()
    cursor = state.last_window_start or (started - _INITIAL_LOOKBACK)
    after = int(cursor.timestamp())
    try:
        payload = await fetch_windows(after)
        windows = sorted(
            (w for w in payload.get("windows") or [] if int(w["window_start"]) > after),
            key=lambda w: int(w["window_start"]),
        )
    except Exception as exc:  # noqa: BLE001 -- recorded, surfaced, never swallowed silently
        state.last_pull_at = started
        state.last_pull_ok = False
        state.last_error = f"{type(exc).__name__}: {exc}"[:500]
        await commit()
        logger.warning("traffic_flow_pull_failed", extra={"error": state.last_error})
        return {"ok": False, "error": state.last_error}

    service = TrafficFlowIngestService(repository)
    exporter_map = await repository.exporter_router_map() if windows else {}
    written = duplicates = 0
    unknown: tuple[str, ...] = tuple(state.unknown_exporters or ())
    for window in windows:
        start = datetime.fromtimestamp(int(window["window_start"]), tz=UTC)
        summary = await service.ingest_window(
            window_start=start,
            window_seconds=int(window.get("window_seconds") or WINDOW_SECONDS),
            rows=window.get("rows") or [],
            exporter_map=exporter_map,
        )
        written += summary.written
        duplicates += summary.duplicates
        unknown = summary.unknown_exporters
        state.last_window_start = start
    state.last_pull_at = started
    state.last_pull_ok = True
    state.last_error = None
    state.unknown_exporters = list(unknown)
    pruned = await repository.delete_windows_before(
        started - timedelta(days=RETENTION_DAYS), limit=RETENTION_BATCH
    )
    await commit()
    result = {
        "pruned": pruned,
        "ok": True,
        "windows": len(windows),
        "written": written,
        "duplicates": duplicates,
        "unknown_exporters": len(unknown),
    }
    logger.info("traffic_flow_pull_completed", extra=result)
    return result


async def _run_async() -> dict[str, Any]:
    import httpx

    from app.database.session import SessionLocal

    settings = get_settings()
    if not settings.traffic_flow_enabled:
        return {"skipped": "disabled"}

    async with (
        httpx.AsyncClient(timeout=AGENT_TIMEOUT_SECONDS) as http,
        SessionLocal() as session,
    ):

        async def fetch(after: int) -> Mapping[str, Any]:
            response = await http.get(
                settings.traffic_flow_agent_url.rstrip("/") + "/flows/windows",
                params={"after": after, "limit": MAX_WINDOWS_PER_PULL},
                headers={"X-Agent-Secret": settings.traffic_flow_agent_secret},
            )
            if response.status_code != 200:
                # The agent's body names the cause; keep it.
                raise RuntimeError(
                    f"agent HTTP {response.status_code}: {response.text[:200]}"
                )
            return response.json()

        return await pull_once(
            repository=TrafficFlowRepository(session),
            settings=settings,
            fetch_windows=fetch,
            commit=session.commit,
        )


@celery_app.task(name=TASK_RUN_TRAFFIC_FLOW_PULL_SWEEP)
def run_traffic_flow_pull_sweep() -> dict[str, Any]:
    """Beat-scheduled every 300 s. Returns immediately while
    ``CLOUDGUEST_TRAFFIC_FLOW_ENABLED`` is false."""
    return run_celery_task(_run_async())

"""Device Logs request/response shapes. Field names are the wire contract
with the Master console (``src/services/deviceLogs.service.ts``)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import MAX_INGEST_BATCH


class IngestEvent(BaseModel):
    """One raw line as the collector received it. Strict: an unexpected
    field means the collector config and this endpoint disagree, which must
    fail loudly, not be ignored (the ``extra='ignore'`` trap)."""

    model_config = ConfigDict(extra="forbid")

    received_at: datetime
    source_ip: str = Field(min_length=1, max_length=64)
    raw: str = Field(max_length=16384)


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[IngestEvent] = Field(max_length=MAX_INGEST_BATCH)


class IngestResult(BaseModel):
    accepted: int
    attributed: int
    unattributed: int
    tag_mismatch: int


class DeviceLogEventView(BaseModel):
    id: int
    received_at: datetime
    device_time: datetime | None
    organization_id: str | None
    organization_name: str | None
    location_id: str | None
    location_name: str | None
    router_id: str | None
    router_name: str | None
    source_ip: str
    vendor: str
    source: str
    facility: int | None
    severity: int | None
    severity_name: str | None
    hostname: str | None
    topics: str | None
    message: str
    attribution: str
    claimed_tag: str | None


class DeviceLogPage(BaseModel):
    feature_enabled: bool
    items: list[DeviceLogEventView]
    next_cursor: str | None
    since: datetime
    until: datetime


class RouterLoggingStatus(BaseModel):
    router_id: str
    router_name: str | None
    organization_id: str | None
    location_id: str | None
    location_name: str | None
    organization_name: str | None
    enabled: bool
    remote_host: str
    remote_port: int
    last_applied_at: datetime | None
    last_verified_at: datetime | None
    verified_ok: bool | None
    verify_detail: str | None
    last_received_at: datetime | None
    #: ``app.domains.device_logs.constants.ReceivingState``.
    state: str


class DeviceLogsOverview(BaseModel):
    feature_enabled: bool
    routers: list[RouterLoggingStatus]
    unattributed_last_24h: int


class RouterLoggingDetail(BaseModel):
    feature_enabled: bool
    router_id: str
    router_name: str
    vendor: str
    location_name: str | None
    organization_name: str | None
    #: Why remote logging cannot be set up on this router right now
    #: (``NOT_MIKROTIK``, ``NO_TUNNEL``, ``NO_API_CREDENTIALS``), or None.
    blocker: str | None
    blocker_detail: str | None
    tunnel_ip: str | None
    status: RouterLoggingStatus | None
    #: Backend-rendered RouterOS paste script (same rows the API writer
    #: uses). None when ``blocker`` is NO_TUNNEL or NOT_MIKROTIK.
    script: list[str] | None
    state: str

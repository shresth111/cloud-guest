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
    category: str | None = None
    protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    status: str | None = None
    device_mac: str | None = None


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


class FirewallLoggingDevice(BaseModel):
    """A live read of the router: the ``WYFY-FW`` rows it holds now."""

    #: Companion rows are on the router.
    enabled: bool
    #: They are exactly what a sync would leave (or there are none).
    ok: bool
    #: ``ready`` / ``missing`` / ``invalid`` -- the forward-chain band.
    band_state: str
    #: Wyfy drop rows that get a companion.
    targets: int
    companions: int
    #: ``"<target comment>: <reason>"`` for drops left without one.
    skipped: list[str]
    detail: str


class FirewallLoggingState(BaseModel):
    router_id: str
    #: Platform switch (``device_logs_firewall_logging_enabled``) AND
    #: ``device_logs_enabled``.
    platform_enabled: bool
    #: A Master turned it on for this router.
    router_enabled: bool
    #: Remote logging is applied on this router (lines have somewhere to go).
    remote_logging_enabled: bool
    #: All three: the rows should be on the router.
    active: bool
    verified_at: datetime | None
    verified_ok: bool | None
    verify_detail: str | None
    #: None when the router could not be read (``device_error`` says why).
    device: FirewallLoggingDevice | None
    device_error: str | None
    #: Hard ceiling and per-rule limit, for the console to show.
    max_lines_per_minute: int
    per_rule_limit: str


class FirewallLoggingRequest(BaseModel):
    enabled: bool


class SessionDeviceEventView(BaseModel):
    """One router event linked to one guest session. No raw line, no host
    name, no user name: kind, time, IP and MAC only."""

    occurred_at: datetime
    #: The router's own clock, best-effort (RFC 3164 carries no year/zone).
    device_time: datetime | None
    #: ``ip_assigned`` | ``ip_released`` | ``router_sign_in`` |
    #: ``router_sign_out``
    kind: str
    ip_address: str
    mac_address: str | None
    #: Sign-out reason in RouterOS's words, when known.
    detail: str | None


class SessionDeviceEvents(BaseModel):
    """``GET /guest-sessions/{id}/device-events``. ``coverage`` says whether
    an empty ``events`` means "nothing happened" (``covered``) or "we could
    not have known" (``not_sending`` / ``not_sending_during_session``)."""

    session_id: str
    coverage: str
    logging_since: datetime | None
    #: False when the session has neither a device MAC nor an IP on record,
    #: so nothing could ever be linked to it.
    linkable: bool
    window_start: datetime
    window_end: datetime
    events: list[SessionDeviceEventView]
    #: Events that matched this session but also another one, so are not
    #: shown (never guessed).
    ambiguous_count: int


# -- customer NetLogs (``/device-logs``) -------------------------------------
# Wire contract with the customer dashboard. Deliberately no ``source_ip``
# (the router's tunnel address), ``claimed_tag`` or ``attribution``: tunnel
# internals are Master-only.


class NetLogEventView(BaseModel):
    id: int
    #: When the platform received the line (the time every filter uses).
    received_at: datetime
    #: The router's own clock, best-effort; None for platform-written rows.
    device_time: datetime | None
    location_id: str | None
    location_name: str | None
    router_id: str | None
    router_name: str | None
    #: The router's identity as it sent it (or the NAS identifier).
    hostname: str | None
    #: ``syslog`` (the router) | ``radius_server`` | ``captive_portal``.
    source: str
    #: ``LogCategory``: dhcp, hotspot_auth, radius, firewall, dns, system,
    #: wireless, other. Never null (unclassified reads ``other``).
    category: str
    protocol: str | None
    src_ip: str | None
    dst_ip: str | None
    #: ``LogStatus``: success, failure, accept, reject, blocked, allowed,
    #: connected, disconnected, released -- or None when the line states no
    #: outcome.
    status: str | None
    device_mac: str | None
    severity: int | None
    severity_name: str | None
    #: Short headline ("IP assigned", "Traffic denied"), or None: show
    #: ``message``.
    summary: str | None
    message: str


class NetLogPage(BaseModel):
    feature_enabled: bool
    items: list[NetLogEventView]
    #: Pass back as ``cursor`` for the next (older) page; None = last page.
    next_cursor: str | None
    #: The effective window after defaults and the 730-day clamp.
    since: datetime
    until: datetime


class NetLogTotals(BaseModel):
    events: int
    #: severity emergency..error (0-3)
    errors: int
    #: severity warning (4)
    warnings: int


class NetLogDay(BaseModel):
    #: Local date (``timezone``), ``YYYY-MM-DD``.
    day: str
    total: int
    errors: int
    warnings: int
    by_category: dict[str, int]


class NetLogTopRouter(BaseModel):
    router_id: str | None
    router_name: str | None
    location_id: str | None
    location_name: str | None
    total: int
    errors: int
    warnings: int


class NetLogSummary(BaseModel):
    feature_enabled: bool
    since: datetime
    until: datetime
    timezone: str
    totals: NetLogTotals
    #: Only days with at least one event, ascending.
    by_day: list[NetLogDay]
    #: Every category key, zero-filled.
    by_category: dict[str, int]
    #: Every severity name plus ``unknown`` (no PRI), zero-filled.
    by_severity: dict[str, int]
    top_routers: list[NetLogTopRouter]

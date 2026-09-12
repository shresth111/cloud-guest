from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class LiveSession(BaseModel):
    """One active guest session, as the "who is online right now" screen shows
    it.

    Four fields below are ``None``-by-absence rather than empty strings or
    zeros, and that distinction is the point of this schema's shape. They were
    previously read off ``GuestSession`` with ``getattr(s, "<name>", <default>)``
    for attribute names **that do not exist on that model** -- ``ssid``,
    ``nas_identifier``, ``router_name``, ``signal_strength``,
    ``session_duration_seconds``, ``guest_username``, ``mac_address``. Every
    one silently returned its default, so the screen rendered a full-looking
    row in which session length was always ``0``, MAC/SSID/NAS/router were
    always ``""``, and the username was the session's own UUID.

    ``None`` now means "this platform does not capture that on the session
    path", which is the honest answer and the same ``available: false``
    posture ``analytics`` already takes for its own gaps:

    * ``ssid`` / ``signal`` -- only ever observed per *device* by the
      15-minute ``connected_devices`` sync (``ConnectedDevice.interface`` /
      ``signal_strength_dbm``), and only for wireless devices. Not carried on
      ``GuestSession``.
    * ``nas`` -- the RADIUS wire identifier lives on ``RadiusNasClient``, keyed
      by router, not on the session.
    * ``router`` -- ``GuestSession`` carries ``router_id`` (now surfaced as
      such); resolving it to a display name is a join this listing does not
      do yet.
    """

    id: str
    # Deliberately NOT the guest's phone/email. This field used to fall back
    # to ``str(session.id)``, so the UI displayed a UUID as a username. The
    # guest's real identifier is PII and is only ever served through a
    # ``MaskedIdentifier``-annotated field (``GuestResponse.identifier``);
    # populating it here as a bare ``str`` would hand out unmasked contact
    # details from a screen that never asked for them. Callers that need the
    # guest should follow ``guest_id``.
    username: str | None = None
    guest_id: str | None = None
    mac: str | None = None
    ip: str | None = None
    ssid: str | None = None
    nas: str | None = None
    router: str | None = None
    router_id: str | None = None
    device: str | None = None
    signal: int | None = None
    session_time_seconds: int = 0
    download_bytes: int = 0
    upload_bytes: int = 0
    status: str = "active"
    location_id: str | None = None
    organization_id: str | None = None
    started_at: datetime | None = None


class LiveSessionListResponse(BaseModel):
    items: list[LiveSession]
    total: int = 0
    page: int = 1
    page_size: int = 25


class SessionActionResponse(BaseModel):
    session_id: str
    action: str
    success: bool = True
    message: str = "Action performed"

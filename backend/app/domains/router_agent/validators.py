"""Pure, side-effect-free business-rule checks for the Router Agent domain.

Every function here takes an already-fetched model instance (or plain
value) and either returns ``None`` or raises one of this module's own
``exceptions``. None of these functions perform I/O -- mirrors
``app.domains.router_provisioning.validators``'s identical discipline of
keeping "what is a legal state" centralized and directly testable in
isolation from any database, consumed here by ``dependencies.py``'s agent
-credential-validation dependency (this module's sole identity-verification
mechanism -- see ``dependencies.py``'s module docstring for why no separate
"verify identity" endpoint exists).

``validate_netwatch_link_owned_by_router``/``netwatch_status_to_ping_result``
back ``router.py``'s ``agent_netwatch_event`` endpoint the identical way --
pure, testable in isolation, no ``IspService``/repository double needed to
exercise either one directly.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from app.domains.isp.device_adapters import PingResult
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router

from .exceptions import (
    AgentCredentialExpiredError,
    AgentCredentialRevokedError,
    AgentRouterNotEligibleError,
    NetwatchLinkNotFoundForRouterError,
)
from .models import RouterAgentCredential

# A router in either of these BE-008 lifecycle statuses has no business
# talking to the agent API: a decommissioned router is permanently retired,
# and a suspended router is administratively frozen pending human action --
# identical reasoning to
# ``router_provisioning.validators._ROUTER_STATUSES_INELIGIBLE_FOR_CONFIG``.
_ROUTER_STATUSES_INELIGIBLE_FOR_AGENT = frozenset(
    {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
)


def validate_router_eligible_for_agent(router: Router) -> None:
    if router.status in _ROUTER_STATUSES_INELIGIBLE_FOR_AGENT:
        raise AgentRouterNotEligibleError(router.id, router.status)


def validate_credential_not_revoked(credential: RouterAgentCredential) -> None:
    if credential.revoked_at is not None:
        raise AgentCredentialRevokedError()


def validate_credential_not_expired(
    credential: RouterAgentCredential, *, now: datetime
) -> None:
    if now > credential.expires_at:
        raise AgentCredentialExpiredError()


def validate_netwatch_link_owned_by_router(
    link_router_id: uuid.UUID, router_id: uuid.UUID, *, isp_link_id: uuid.UUID
) -> None:
    """``POST /agent/netwatch-event``'s own ownership check: the
    ``IspLink`` the caller reported must actually belong to *this*
    credential's own router -- ``router_id`` always comes from the
    credential itself (never client-supplied, see ``dependencies.py``'s
    own module docstring), so this is the one remaining fact that isn't
    already server-derived. Mirrors
    ``app.domains.router_provisioning.validators.validate_job_belongs_to_router``'s
    identical shape for the action-queue's own ownership check."""
    if link_router_id != router_id:
        raise NetwatchLinkNotFoundForRouterError(str(isp_link_id))


def netwatch_status_to_ping_result(status: str) -> PingResult:
    """Synthesizes the exact ``PingResult`` shape
    ``IspService.record_health_check_result`` already expects from a real
    ping, from a Netwatch up/down signal instead -- the identical "0%
    loss for up, 100% loss/no latency for down" synthesis
    ``IspService.ping_link`` already performs for its own PPPOE-mode
    links (see that method's own docstring), reused here so a
    Netwatch-detected change advances the exact same
    ``consecutive_unhealthy_count``/failover pipeline the 30-second sweep
    does -- one recording path, now three ways to arrive at it, not a
    second, parallel health signal.

    ``status`` is validated at the schema layer
    (``AgentNetwatchEventRequest``) to be exactly ``"up"``/``"down"`` --
    this function trusts that already-validated value rather than
    re-validating it a second time."""
    if status == "up":
        return PingResult(
            sent=1, received=1, packet_loss_percentage=0.0, avg_rtt_ms=0.0
        )
    return PingResult(
        sent=1, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
    )


_ROUTEROS_MAC = re.compile(
    r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})"
    r"[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$"
)


def routeros_mac_address(value: object) -> str | None:
    """``value`` spelled the one way RouterOS itself spells a MAC --
    ``AA:BB:CC:DD:EE:FF`` -- or ``None`` if it is not a six-octet MAC.

    ``GET /agent/authorized-macs`` is consumed by a script on the router,
    not by a person, and the script has no way to cope with anything else:

    * It asks the router ``find where mac-address=<entry>``. A value
      RouterOS cannot parse as a MAC is a script error, and the script's
      statements run as one unit -- so a single malformed entry stops the
      sync for *every* guest at that venue, admitted or leaving.
    * It decides "is this binding's MAC still listed?" by comparing the
      router's own spelling against this list. A second spelling of the
      same address reads as "not listed", and the binding is removed and
      re-added on every one-minute tick; RouterOS drops the device's
      connection each time a binding changes.

    ``guest_devices.mac_address`` is upper-cased on the way in but is
    otherwise whatever a portal request carried, so the list is normalised
    here, at the one place it leaves the platform. Never raises."""
    if not isinstance(value, str):
        return None
    match = _ROUTEROS_MAC.match(value.strip())
    if match is None:
        return None
    return ":".join(octet.upper() for octet in match.groups())


__all__ = [
    "routeros_mac_address",
    "validate_router_eligible_for_agent",
    "validate_credential_not_revoked",
    "validate_credential_not_expired",
    "validate_netwatch_link_owned_by_router",
    "netwatch_status_to_ping_result",
]

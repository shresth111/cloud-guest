"""ISP Management domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "IspError",
    "IspLinkNotFoundError",
    "CrossOrganizationIspLinkAccessError",
    "IspPrimaryLinkAlreadyExistsError",
    "IspNoBackupLinkAvailableError",
    "IspLinkDisabledError",
    "IspHealthCheckTargetUnavailableError",
    "IspMissingCredentialsError",
    "IspDeviceConnectionError",
    "IspDeviceOperationError",
    "UnsupportedIspVendorError",
    "IspSpeedTestCooldownError",
    "MixedWanRoutingWeightsError",
    "IspLinkInterfaceRequiredError",
    "IspLinkInterfaceInvariantError",
    "IspLinkRoutingInterfaceUnknownError",
    "IspFailoverTargetUnreachableError",
    "IspAmbiguousDefaultRouteError",
    "IspDeviceRouteMismatchError",
    "IspRouteImmutableError",
]


class IspError(CloudGuestError):
    """Base exception for ISP Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class IspLinkNotFoundError(IspError):
    def __init__(self, link_id: uuid.UUID | str) -> None:
        super().__init__(
            f"ISP link not found: {link_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationIspLinkAccessError(IspError):
    """A caller acting within organization A attempted to read/mutate an
    ISP link belonging to organization B -- mirrors
    ``app.domains.router.exceptions.CrossOrganizationRouterAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access an ISP link belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class IspPrimaryLinkAlreadyExistsError(IspError):
    """A router may hold exactly one ``IspLinkRole.PRIMARY`` link at a
    time -- raised by ``create_link``/``update_link`` when a second
    primary is requested for a router that already has one. An admin must
    first re-role the existing primary to ``BACKUP`` (or delete it)
    before promoting a different link."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' already has a primary ISP link -- "
            "re-role or remove it before assigning a new one",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspNoBackupLinkAvailableError(IspError):
    """``trigger_failover`` found no enabled, healthy (or at least not
    currently-unhealthy) ``BACKUP`` link to fail over to -- the primary's
    own outage is real, but there is nothing safe to switch traffic onto."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no available backup ISP link to " "fail over to",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspLinkDisabledError(IspError):
    """A caller attempted to health-check, activate, or fail over to a
    link with ``is_enabled=False`` -- an admin has deliberately taken it
    out of service."""

    def __init__(self, link_id: uuid.UUID) -> None:
        super().__init__(
            f"ISP link '{link_id}' is disabled and cannot be used",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspHealthCheckTargetUnavailableError(IspError):
    """Raised by ``IspService.ping_link`` when a DHCP/PPPOE-mode link's
    own real target can't be resolved right now -- a DHCP link with no
    *active* default route (dynamic or static -- see
    ``device_adapters.BaseIspHealthAdapter.get_active_default_gateway``'s
    own docstring for why a static fallback is checked too) currently
    present on the router, or a PPPOE link with no ``interface``
    configured at all. Distinct from
    ``IspMissingCredentialsError`` (that one is about the router's own
    API connection details being absent; this one is about the *link's*
    own connection-mode-specific target, reachable router or not). The
    platform-wide sweep's own per-link isolation catches this exactly
    like any other per-link failure -- it is never a reason to fail the
    whole sweep."""

    def __init__(self, link_id: uuid.UUID, reason: str) -> None:
        super().__init__(
            f"ISP link '{link_id}' health-check target unavailable: {reason}",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspMissingCredentialsError(IspError):
    """Raised when a router has no management IP/username/decrypted
    secret stored -- the same real gap
    ``app.domains.queue_management.exceptions.QueueMissingCredentialsError``
    documents, applied to ISP link health-check operations."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class IspDeviceConnectionError(IspError):
    """Could not open a real RouterOS API connection to the router at
    all -- mirrors
    ``app.domains.queue_management.exceptions.QueueDeviceConnectionError``."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(
            f"Could not connect to router at '{host}': {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class IspDeviceOperationError(IspError):
    """A connection was opened, but the RouterOS command itself failed
    (e.g. ``/tool/ping`` returned a ``!trap``) -- mirrors
    ``app.domains.queue_management.exceptions.QueueDeviceOperationError``."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            f"ISP device operation '{operation}' failed: {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class IspSpeedTestCooldownError(IspError):
    """A speed test genuinely consumes real, possibly-metered customer
    bandwidth and briefly saturates a low-power router -- ``run_speed_test``
    enforces a real per-link cooldown (``constants
    .SPEED_TEST_MIN_INTERVAL_SECONDS``) so this on-demand action can't be
    hammered back-to-back (accidentally, by two admins racing each other,
    or maliciously) into a real bandwidth/availability problem for the
    customer's own network. ``retry_after_seconds`` is the real, live TTL
    remaining on the Redis cooldown key, not a fixed guess."""

    def __init__(self, link_id: uuid.UUID, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"A speed test already ran recently on ISP link '{link_id}' -- "
            f"try again in {retry_after_seconds}s",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class UnsupportedIspVendorError(IspError):
    """No health-check adapter is registered for this router's own
    ``vendor`` -- mirrors
    ``app.domains.queue_management.exceptions.UnsupportedQueueVendorError``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No ISP health-check adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class IspLinkInterfaceRequiredError(IspError):
    """Raised by ``IspService.get_or_create_link_for_interface`` -- unlike
    plain ``create_link`` (where ``interface`` is optional -- an admin can
    add a link before wiring the physical/PPPoE interface), this method's
    entire dedupe key *is* ``(router_id, interface)``. A caller with no
    interface to key off has nothing to be idempotent against and should
    call ``create_link`` directly instead."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"An interface is required to get-or-create an ISP link for "
            f"router '{router_id}' -- call create_link directly if the "
            "interface is genuinely unknown",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class IspLinkInterfaceInvariantError(IspError):
    """Raised when physical/routing interface fields or PPPoE credentials
    violate the WAN split invariants enforced in
    ``validators.normalize_isp_link_interfaces``."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class MixedWanRoutingWeightsError(IspError):
    """Raised by ``validators.validate_wan_routing_weights`` when a router
    in ``WanRoutingMode.LOAD_BALANCE`` has *some* but not *all* of its
    enabled links weighted -- see that function's own docstring for why a
    partial weighting is rejected outright rather than silently defaulting
    the unweighted links to an even split among themselves."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has a load-balance weight set on some "
            "but not all of its enabled WAN links -- weight either every "
            "enabled link or none of them",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# WAN failover -- refusals that happen instead of a guess
# ============================================================================
#
# Every one of these is a state in which moving a venue's live traffic would
# be an act of hope. A failover onto a link that is also down does not
# restore a site: it adds a second outage to the first and leaves the
# dashboard's "Active uplink" tile naming an uplink no packet uses, which is
# the single screen a customer looks at while they are already offline.
# Refusing names the problem and leaves the router exactly as it was.


class IspLinkRoutingInterfaceUnknownError(IspError):
    """The link traffic would move onto has no interface recorded, so
    there is no way to name what to move it to.

    Checked before a socket is opened. Nothing on the device can be
    resolved from a link whose ``routing_interface``/``interface`` is
    NULL, and inferring one ("the router only has one other WAN port")
    would be a guess about a customer's cabling."""

    def __init__(self, link_id: uuid.UUID) -> None:
        super().__init__(
            f"ISP link '{link_id}' has no WAN interface recorded, so traffic "
            "cannot be moved onto it -- set the link's interface first",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspFailoverTargetUnreachableError(IspError):
    """The router's own live state says the link being failed over to is
    not usable right now.

    Raised after a read and before any write, on either of two real
    signals: the target's default route is not RouterOS-``active`` (its
    ``check-gateway`` probe is failing, or it is administratively
    disabled), or the router cannot ping the target's own next hop.

    This is the check that stops the worst outcome available here. What it
    does *not* prove is that the internet is reachable beyond that next
    hop -- see ``IspService._verify_failover_target``."""

    def __init__(self, link_id: uuid.UUID, reason: str) -> None:
        super().__init__(
            f"ISP link '{link_id}' is not usable as a failover target right "
            f"now: {reason}",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspAmbiguousDefaultRouteError(IspError):
    """The router has more than one plausible default route for the
    uplink in question, or several tied at the lowest distance.

    Both are states where "which route is this link's" has no single
    answer, and picking the first row would be choosing by reply order.
    Worse, a distance change made into a tie is RouterOS load sharing --
    so guessing here can split a venue's traffic across an uplink that is
    down rather than moving it off one."""

    #: ``target`` is the owning router's id when this domain's own service
    #: layer raises it (which is the readable case for an operator) and the
    #: device host when the adapter does -- the adapter genuinely does not
    #: know the router id, and inventing one to fill the field would put a
    #: wrong uuid in a customer-visible message.
    def __init__(self, target: uuid.UUID | str, reason: str) -> None:
        super().__init__(
            f"Router '{target}' has an ambiguous default-route layout, so "
            f"failover cannot say which route to move: {reason}",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspDeviceRouteMismatchError(IspError):
    """The router's routing table does not contain what this platform's
    database says it should.

    Specifically: the database holds an ISP link terminating on an
    interface for which the router has no ``main``-table default route at
    all. The two disagree about the site's topology, and a failover
    carried out on the database's belief would write a preference for a
    path the router does not have."""

    #: ``target`` follows the same router-id-or-host convention as
    #: :class:`IspAmbiguousDefaultRouteError`.
    def __init__(self, target: uuid.UUID | str, reason: str) -> None:
        super().__init__(
            f"Router '{target}' does not confirm the topology this platform "
            f"believes it has, so failover is refused: {reason}",
            status_code=status.HTTP_409_CONFLICT,
        )


class IspRouteImmutableError(IspError):
    """The default route that would have to be modified is one RouterOS
    created itself (a dhcp-client auto-route) and refuses to let anyone
    change.

    Real and expected on a router not provisioned by this platform's own
    Setup Script generator, which deliberately sets ``add-default-route=no``
    on every dhcp-client and provisions a *static* default route per WAN
    instead -- precisely so this platform's routing decisions are ones it
    is allowed to make."""

    #: ``target`` follows the same router-id-or-host convention as
    #: :class:`IspAmbiguousDefaultRouteError`.
    def __init__(self, target: uuid.UUID | str, reason: str) -> None:
        super().__init__(
            f"Router '{target}' cannot be failed over: {reason}. Re-run "
            "this router's setup script so its default routes are static and "
            "platform-managed.",
            status_code=status.HTTP_409_CONFLICT,
        )

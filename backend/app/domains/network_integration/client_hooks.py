"""Per-client controller writes for callers that cannot hold a
``NetworkIntegrationService``.

Three hooks live here -- ending one client's session, setting or clearing one
client's speed limit, and blocking or unblocking one client's device -- and
they share one tenant-scoped resolution.

## Why this is a module and not a method

``LiveSessionTerminator`` (``app.domains.guest_access.enforcement``) needs to
end a session on a venue whose network is run from a controller. The obvious
move -- inject ``NetworkIntegrationService`` -- does not work, and it is worth
writing down why, because it looks like it should.

**There is an import cycle.** ``network_integration.dependencies`` imports
``guest.dependencies`` (it composes ``GuestService`` to end the platform-side
session after a disconnect). So ``guest.dependencies`` cannot import
``network_integration.dependencies`` back.

**And there is an object cycle behind it.** ``NetworkIntegrationService``
already holds a ``guest_session_terminator``, which *is* the
``LiveSessionTerminator``; it also composes ``GuestService``, which composes
``QueueManagementService``, which is the other caller here. Handing either of
them a ``NetworkIntegrationService`` would not merely close an import loop --
it would recurse while being constructed.

So this is the narrow half instead: one function over the repository and the
provider seam, holding nothing and composing nothing. It reuses the same
tenant-scoped repository query and the same provider the service uses, so
there is no second copy of either rule -- only a smaller entry point.

## What it does and does not achieve

It ends the client's authorization on the controller: the device stops being
forwarded. It does **not** write the platform-side session row, and it must
not -- every caller reaches here *after* its own status transition has
committed (see ``guest.service.issue_live_disconnect``'s docstring), and a
second writer here would be racing them.

It also does not stop the guest signing in again. That is the platform's own
blocklist, which is vendor-neutral and is consulted at every login and by the
RADIUS authorize path.

## Session timeout, specifically

This is the controller half of session timeout for an Omada venue, and the
honest description of that feature is: **expiry is decided here, on this
platform, by the existing sweep, and the controller is then told to drop the
client.** The controller does not enforce it. It honours no RADIUS
``Session-Timeout`` -- its own API specification contains no occurrence of the
attribute, nor of any bandwidth sibling -- so unlike a RouterOS venue, where
the reply attribute makes the NAS itself end the session, nothing at an Omada
venue will end a session if this platform's sweep does not run.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.domains.guest_access.constants import BlockEnforcementStatus
from app.domains.guest_access.enforcement import (
    ControllerBlockOutcome,
    ControllerReleaseOutcome,
)

from .constants import (
    DEFAULT_CONTROLLER_TLS_MODE,
    IntegrationEventStatus,
    IntegrationEventType,
)
from .crypto import (
    NetworkIntegrationCredentialDecryptionError,
    decrypt_credentials,
)
from .exceptions import (
    ClientActionUnavailableError,
    LocationHasNoControllerError,
    NetworkIntegrationUrlRejectedError,
    ProviderClientNotFoundError,
    ProviderError,
)
from .models import NetworkIntegration
from .providers import get_network_provider
from .providers.base import ProviderConnectionConfig
from .repository import NetworkIntegrationRepository
from .validators import normalize_client_mac

logger = logging.getLogger(__name__)

__all__ = [
    "build_controller_activity_reporting_lookup",
    "build_controller_device_blocker",
    "build_controller_session_terminator",
    "build_controller_speed_hook",
]


@dataclass(frozen=True, slots=True)
class _ResolvedController:
    integration: NetworkIntegration
    provider: object
    config: ProviderConnectionConfig
    site_id: str


async def _resolve(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
) -> _ResolvedController | None:
    """The venue's controller, or ``None``.

    **Tenant-scoped by the query, not by a check afterwards.** The caller's
    organization and the location are both in the WHERE clause, so a location
    belonging to another tenant resolves to nothing -- there is no path here
    that reads another tenant's controller and then declines to use it. The
    site the write then runs against comes from the row this returned, never
    from a caller-supplied value.
    """
    if organization_id is None:
        return None
    repository = NetworkIntegrationRepository(session)
    integration = await repository.get_omada_integration_for_location(
        location_id=location_id, organization_id=organization_id
    )
    if integration is None or not integration.external_site_id:
        return None
    if not integration.credentials_encrypted:
        return None
    settings = get_settings()
    try:
        credentials = decrypt_credentials(
            integration.credentials_encrypted, settings=settings
        )
    except NetworkIntegrationCredentialDecryptionError:
        logger.exception(
            "network_integration_client_hook_credentials_unreadable",
            extra={"integration_id": str(integration.id)},
        )
        return None
    return _ResolvedController(
        integration=integration,
        provider=get_network_provider(integration.provider),
        config=_connection_config(integration, credentials, settings),
        site_id=str(integration.external_site_id),
    )


def build_controller_speed_hook(session: AsyncSession):
    """Setting and clearing one client's speed limit, bound to ``session``.

    Satisfies ``queue_management.service.ControllerSpeedHookProtocol``, so a
    ``QueueProfile`` applied at a controller-managed venue reaches the
    controller's own per-client rate limit. There is deliberately no second
    speed model for these venues: same profile, same kbps, different
    transport.

    **The capability is checked before the call**, from the integration's own
    auth mode, so a venue connected with a hotspot operator login is refused
    with the provider's own reason rather than by a controller error that
    reads like a network fault.

    Raises rather than degrading. A recorded speed limit the venue never
    received is exactly the silent success this must not produce.
    """

    class _SpeedHook:
        @staticmethod
        async def set_client_speed(
            *,
            location_id: uuid.UUID,
            organization_id: uuid.UUID | None,
            client_mac: str,
            down_kbps: int | None,
            up_kbps: int | None,
            actor_user_id: uuid.UUID | None = None,
        ) -> object:
            resolved = await _require(
                session,
                location_id=location_id,
                organization_id=organization_id,
                action="set_rate_limit",
            )
            mac = _require_mac(client_mac)
            try:
                applied = await resolved.provider.set_client_rate_limit(
                    resolved.config,
                    resolved.site_id,
                    mac,
                    down_kbps=down_kbps,
                    up_kbps=up_kbps,
                )
            except ProviderError as error:
                await _record_client_failure(
                    session,
                    resolved,
                    action="set_rate_limit",
                    client_mac=mac,
                    error=error,
                    context={
                        "requested_down_kbps": down_kbps,
                        "requested_up_kbps": up_kbps,
                    },
                )
                raise
            await _record_client_success(
                session,
                resolved,
                action="set_rate_limit",
                client_mac=mac,
                context={
                    "requested_down_kbps": down_kbps,
                    "requested_up_kbps": up_kbps,
                    # What the controller was actually given, which is not
                    # always what was asked for -- its per-client limit is a
                    # number in 1..1024 plus a Kbps/Mbps unit, so a profile
                    # above that ceiling, or one that does not land on a whole
                    # Mbps, is clamped or rounded on the way out. Recording the
                    # applied figure beside the requested one is what lets a
                    # venue see the cap it really has rather than the one it
                    # typed.
                    "applied_down_kbps": getattr(applied, "applied_down_kbps", None),
                    "applied_up_kbps": getattr(applied, "applied_up_kbps", None),
                    "clamped": bool(getattr(applied, "clamped", False)),
                },
            )
            return applied

        @staticmethod
        async def clear_client_speed(
            *,
            location_id: uuid.UUID,
            organization_id: uuid.UUID | None,
            client_mac: str,
            actor_user_id: uuid.UUID | None = None,
        ) -> object:
            resolved = await _require(
                session,
                location_id=location_id,
                organization_id=organization_id,
                action="clear_rate_limit",
            )
            mac = _require_mac(client_mac)
            try:
                cleared = await resolved.provider.clear_client_rate_limit(
                    resolved.config, resolved.site_id, mac
                )
            except ProviderError as error:
                await _record_client_failure(
                    session,
                    resolved,
                    action="clear_rate_limit",
                    client_mac=mac,
                    error=error,
                )
                raise
            await _record_client_success(
                session, resolved, action="clear_rate_limit", client_mac=mac
            )
            return cleared

    return _SpeedHook()


async def _record_client_success(
    session: AsyncSession,
    resolved: _ResolvedController,
    *,
    action: str,
    client_mac: str,
    context: dict[str, object] | None = None,
) -> None:
    """One row in the venue's own integration feed, per automatic write.

    Serves every client hook in this module -- speed, block and unblock --
    because they are the same fact: this platform wrote to a venue's
    controller without anybody clicking a button, and the venue must be able
    to see it.

    The manual per-client route already records both outcomes through
    ``NetworkIntegrationService._record_client_action``; this is the same feed
    and the same event type for the writes *nobody clicked* -- a guest login,
    a policy publish, a schedule window. Without it the automatic path was the
    only speed write on the platform that left no trace: the assignment row
    said ``ACTIVE`` and the venue had no way to see what its controller had
    actually been told, or that it had been told nothing.
    """
    await _create_event(
        session,
        resolved,
        status=IntegrationEventStatus.OK,
        error_code=None,
        message=f"Client {action} succeeded",
        context={"action": action, "client_mac": client_mac, **(context or {})},
    )


async def _record_client_failure(
    session: AsyncSession,
    resolved: _ResolvedController,
    *,
    action: str,
    client_mac: str,
    error: ProviderError,
    context: dict[str, object] | None = None,
) -> None:
    """The refusal, written down before it is re-raised or returned.

    **The controller cannot rate-limit a client it cannot currently see**, and
    that is the refusal this path meets most often: a guest whose device has
    dropped off the site between authenticating and this write has no
    known-client record to carry a ``rateLimit`` field, and the controller
    says so. Some of those refusals are named -- the provider maps the
    measured client-does-not-exist codes onto
    :class:`ProviderClientNotFoundError` -- and some arrive from a layer in
    front of the handler, where the only thing this platform is given is the
    controller's own raw code. So both are recorded: the normalized
    ``error_code`` *and* ``provider_code``, the integer the controller
    actually returned.

    That distinction is the point. A refusal this platform cannot yet name is
    still a refusal, and filing it under a generic "could not reach the
    controller" is how a venue ends up believing a speed was applied. An
    unnamed code recorded verbatim can be read off a real venue's feed and
    turned into a named one; a swallowed one cannot.

    Never the last word on the guest, either. This runs on a best-effort
    queueing path that has already let the guest online, and the caller
    re-raises into ``apply_queue``, which writes the message onto the
    assignment row and leaves it out of ``ACTIVE``. Nothing here decides
    whether anybody gets internet.
    """
    await _create_event(
        session,
        resolved,
        status=IntegrationEventStatus.ERROR,
        error_code=getattr(error, "code", None),
        message=str(error) or f"Client {action} failed",
        context={
            "action": action,
            "client_mac": client_mac,
            "provider_code": getattr(error, "provider_code", None),
            **(context or {}),
        },
    )


async def _create_event(
    session: AsyncSession,
    resolved: _ResolvedController,
    *,
    status: IntegrationEventStatus,
    error_code: str | None,
    message: str | None,
    context: dict[str, object],
) -> None:
    """Append to ``network_integration_events``, redacted, never raising.

    Redacted through the same :func:`redact_context` the service uses --
    these two columns render straight into the customer dashboard, so the
    redaction is a data-exfiltration control and not a logging nicety.

    Swallows its own failure on purpose. This is bookkeeping wrapped around a
    device write whose result the caller is about to act on; a feed insert
    that fails must not convert a successful speed write into an exception, or
    replace the controller's own refusal with a database error and lose the
    real reason.
    """
    # Imported here, not at module scope: ``service.py`` is the module this
    # one exists to not import (see the module docstring). A function-scope
    # import borrows the one pure, dictionary-only helper without taking on
    # the service's construction graph, and keeps the single definition of
    # what counts as a secret-shaped key.
    from .service import redact_context  # noqa: PLC0415

    try:
        repository = NetworkIntegrationRepository(session)
        await repository.create_event(
            integration_id=resolved.integration.id,
            organization_id=resolved.integration.organization_id,
            event_type=IntegrationEventType.CLIENT_MANAGED.value,
            status=status.value,
            error_code=error_code,
            message=message,
            context=redact_context(context),
        )
    except Exception:  # noqa: BLE001 -- bookkeeping, see docstring
        logger.warning(
            "network_integration_client_hook_event_unrecorded",
            extra={"integration_id": str(resolved.integration.id)},
        )


async def _require(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    action: str,
) -> _ResolvedController:
    """:func:`_resolve`, but a missing controller is an error.

    The speed path raises where the disconnect path returns ``False``,
    because the two callers need different things: the disconnect runs after
    a status transition that has already committed and reports enforcement by
    a boolean, while the speed write is the whole point of the call and a
    quiet ``False`` there would be a limit nobody applied and nobody was told
    about.
    """
    resolved = await _resolve(
        session, location_id=location_id, organization_id=organization_id
    )
    if resolved is None:
        raise LocationHasNoControllerError()
    capability = getattr(resolved.provider.client_capabilities(resolved.config), action)
    if not capability.supported:
        raise ClientActionUnavailableError(
            action, capability.reason or "This action is not available here."
        )
    return resolved


def _require_mac(client_mac: str) -> str:
    try:
        return normalize_client_mac(client_mac)
    except ValueError as exc:
        raise NetworkIntegrationUrlRejectedError(str(exc)) from exc


def build_controller_device_blocker(session: AsyncSession):
    """Blocking and unblocking one device on a venue's controller, bound to
    ``session``.

    Satisfies ``guest_access.enforcement.ControllerDeviceBlockerProtocol``,
    so a ``BLOCKLIST`` rule written on the customer dashboard reaches the
    venue's controller as well as this platform's own login gate. The caller
    supplies the database session once, at wiring time; the hook's own
    signatures stay free of it, and ``BlocklistEnforcer`` -- which has no
    session and must not grow one -- never sees it.

    ## Why it returns outcomes instead of raising

    Every other write in this module raises, because for those the write is
    the whole point of the call. Here it is not. The operator asked for a
    person to be blocked, and that has already happened, vendor-neutrally,
    in this platform's own tables; the device write is an additional
    deterrent on top. A controller that refuses to block one of five phones
    must not turn that into a failed block -- but it must also never be
    silently dropped, which is why the refusal comes back as a value, with
    the vendor's own code, and is written to a row the caller keeps.

    ## Tenant-scoped by the query, not by a check afterwards

    Inherited from :func:`_resolve`: the caller's organization and the
    location are both in the WHERE clause, so a location belonging to
    another tenant resolves to nothing. The site every write runs against
    comes from the row that resolved, never from anything a caller named --
    no customer path anywhere gives this an integration or a site id.
    """

    class _DeviceBlocker:
        @staticmethod
        async def controller_present(
            *, location_id: uuid.UUID, organization_id: uuid.UUID | None
        ) -> bool:
            """One indexed lookup, answered before anything else happens.

            This is what keeps a RouterOS venue out of the whole path: it
            resolves nothing, decrypts nothing, calls nothing, and the
            caller stops here.
            """
            return (
                await _resolve(
                    session,
                    location_id=location_id,
                    organization_id=organization_id,
                )
                is not None
            )

        @staticmethod
        async def block_device(
            *,
            location_id: uuid.UUID,
            organization_id: uuid.UUID | None,
            client_mac: str,
        ) -> ControllerBlockOutcome:
            return await _client_block_action(
                session,
                location_id=location_id,
                organization_id=organization_id,
                client_mac=client_mac,
                action="block",
            )

        @staticmethod
        async def release_device(
            *,
            location_id: uuid.UUID,
            organization_id: uuid.UUID | None,
            client_mac: str,
        ) -> ControllerReleaseOutcome:
            outcome = await _client_block_action(
                session,
                location_id=location_id,
                organization_id=organization_id,
                client_mac=client_mac,
                action="unblock",
            )
            # A release aimed at a client the controller has no record of
            # has nothing left to do, and saying so is not the same as
            # claiming a write landed: there is no block on that MAC at this
            # site, which is the state the caller wanted. Anything else --
            # a refusal, an unreachable controller, a venue that cannot
            # block at all -- leaves the stored row uncleared so the next
            # attempt finds it again.
            released = outcome.status in (
                BlockEnforcementStatus.ENFORCED.value,
                BlockEnforcementStatus.NOT_APPLICABLE.value,
            )
            return ControllerReleaseOutcome(
                released=released,
                error_message=None if released else outcome.error_message,
            )

    return _DeviceBlocker()


async def _client_block_action(
    session: AsyncSession,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID | None,
    client_mac: str,
    action: str,
) -> ControllerBlockOutcome:
    """One ``block``/``unblock`` write, reported rather than raised.

    The four answers this can give are the four values of
    ``BlockEnforcementStatus``, and the distinctions are the point:

    * ``UNENFORCED`` -- there is no controller here, or the one that is
      here cannot block at all. The second is the hotspot-operator
      (``legacy``) case, gated on the provider's own declared capability and
      reported with the provider's own reason. There is no fallback and no
      second mechanism: a venue connected that way simply cannot do this,
      and pretending otherwise would put a green tick on a venue where
      nothing happened.
    * ``NOT_APPLICABLE`` -- the controller has no record of this device.
      Nothing to block, nothing refused. Distinguished by the vendor's own
      normalized not-found code and never folded into the line below.
    * ``FAILED`` -- the controller knows the device and would not do it, or
      could not be reached.
    * ``ENFORCED`` -- the controller confirmed it.

    The MAC is normalized here and only here; a value that is not
    MAC-shaped is a ``FAILED`` outcome rather than an exception, because the
    caller is iterating devices and one malformed stored row must not stop
    the other four.
    """
    resolved = await _resolve(
        session, location_id=location_id, organization_id=organization_id
    )
    if resolved is None:
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=client_mac,
            status=BlockEnforcementStatus.UNENFORCED.value,
            error_message=(
                "This venue's network is not run from a controller this "
                "platform is connected to, so there is nothing to block on."
            ),
        )
    capability = getattr(resolved.provider.client_capabilities(resolved.config), action)
    if not capability.supported:
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=client_mac,
            status=BlockEnforcementStatus.UNENFORCED.value,
            error_message=capability.reason or "This action is not available here.",
        )
    try:
        mac = normalize_client_mac(client_mac)
    except ValueError as exc:
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=client_mac,
            status=BlockEnforcementStatus.FAILED.value,
            error_message=str(exc),
        )

    call = (
        resolved.provider.block_client
        if action == "block"
        else resolved.provider.unblock_client
    )
    try:
        performed = bool(await call(resolved.config, resolved.site_id, mac))
    except ProviderClientNotFoundError as error:
        await _record_client_failure(
            session, resolved, action=action, client_mac=mac, error=error
        )
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=mac,
            status=BlockEnforcementStatus.NOT_APPLICABLE.value,
            error_code=getattr(error.code, "value", None),
            error_message=str(error),
        )
    except ProviderError as error:
        await _record_client_failure(
            session, resolved, action=action, client_mac=mac, error=error
        )
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=mac,
            status=BlockEnforcementStatus.FAILED.value,
            error_code=getattr(error.code, "value", None),
            error_message=str(error),
        )
    await _record_client_success(session, resolved, action=action, client_mac=mac)
    if not performed:
        # The controller answered without an error and without doing it.
        # Rare, and not something to render as success: "we asked and it
        # said nothing happened" is a refusal with no reason attached.
        return ControllerBlockOutcome(
            location_id=location_id,
            mac_address=mac,
            status=BlockEnforcementStatus.FAILED.value,
            error_message=(f"The controller did not confirm the {action}."),
        )
    return ControllerBlockOutcome(
        location_id=location_id,
        mac_address=mac,
        status=BlockEnforcementStatus.ENFORCED.value,
    )


def build_controller_session_terminator(session: AsyncSession):
    """A callable that ends one client's controller session, bound to
    ``session``.

    Returned rather than exported directly so the caller supplies the database
    session once, at wiring time, and the terminator's own signature stays
    free of it -- ``LiveSessionTerminator`` has no session and should not grow
    one.

    The returned callable also carries a ``release_rate_limit`` attribute:
    a second, independently callable operation, hung on the function rather
    than given its own builder so that what is returned is still exactly the
    callable ``ControllerSessionTerminatorProtocol`` describes and every
    existing caller and wiring site is untouched. It exists because
    releasing this platform's speed limit and ending the session are **not**
    the same event and must not share a fate -- see
    :func:`_release_rate_limit`.
    """

    async def terminate(
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> bool:
        """End every live authorization ``client_mac`` holds at this location.

        **Tenant-scoped by the query, not by a check afterwards.** The
        integration is resolved with the caller's organization *and* the
        location in the WHERE clause, so a location belonging to another
        tenant resolves to nothing and this returns ``False`` -- it never
        reads another tenant's controller and then declines to use it.

        Returns ``False`` rather than raising when there is no controller to
        talk to: the caller is the enforcement path, which has already
        committed a status transition and distinguishes "we did it" from "we
        could not" by this boolean. A controller that answers with an error
        still raises, because that is a different fact and the caller logs it
        as one.
        """
        resolved = await _resolve(
            session, location_id=location_id, organization_id=organization_id
        )
        if resolved is None:
            return False
        integration = resolved.integration
        try:
            normalized = normalize_client_mac(client_mac)
        except ValueError:
            # The identifier the enforcement path carries is the portal
            # ``user`` -- a phone number for an OTP guest -- and only
            # sometimes a MAC. Not MAC-shaped means there is nothing to
            # address the controller with, which is a "could not", not an
            # error: the caller logs it and reports enforcement as not
            # delivered.
            logger.info(
                "network_integration_controller_disconnect_no_mac",
                extra={"integration_id": str(integration.id)},
            )
            return False

        try:
            ended = bool(
                await resolved.provider.deauthorize_guest(
                    resolved.config, resolved.site_id, normalized
                )
            )
        except ProviderError:
            logger.warning(
                "network_integration_controller_disconnect_failed",
                extra={
                    "integration_id": str(integration.id),
                    "enforcement_delivered": False,
                },
            )
            # Still take the limit off. A deauthorize that failed is exactly
            # the case where the limit is most likely to be left standing,
            # and the release is not conditional on this platform having
            # been the one to end the session -- see ``_release_rate_limit``.
            await _release_rate_limit(session, resolved, client_mac=normalized)
            raise

        await _release_rate_limit(session, resolved, client_mac=normalized)
        return ended

    async def release_rate_limit(
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        client_mac: str,
    ) -> None:
        """Take this platform's speed limit off ``client_mac``, without
        ending anything.

        The separate entry point for the sessions this platform did not end
        on the device: a RADIUS Accounting-Stop, or the controller's own
        timeout. Those never reach ``terminate`` -- correctly, since there
        is nothing left to disconnect -- and used to carry the release with
        them, so at a RADIUS-mode venue, where an Accounting-Stop is the
        *ordinary* way a session ends, the limit was never removed at all.

        Silent and non-raising, like the release inside ``terminate``: the
        caller is a session end that has already committed.
        """
        resolved = await _resolve(
            session, location_id=location_id, organization_id=organization_id
        )
        if resolved is None:
            return
        try:
            normalized = normalize_client_mac(client_mac)
        except ValueError:
            return
        await _release_rate_limit(session, resolved, client_mac=normalized)

    terminate.release_rate_limit = release_rate_limit  # type: ignore[attr-defined]
    return terminate


async def _release_rate_limit(
    session: AsyncSession,
    resolved: _ResolvedController,
    *,
    client_mac: str,
) -> None:
    """Take this platform's speed limit back off the MAC the session used.

    **Why session end, and why here.** A controller's per-client limit is a
    field on the *known-client* record, keyed by MAC within the site. It has
    no session lifetime: it outlives the authorization that caused it, it
    survives the client going offline, and nothing on the controller ever
    removes it. So without this the next device to hold that MAC inherits a
    cap nobody configured for it -- the same defect RouterOS venues already
    produced with accumulating ``/queue simple`` rows, where one guest was
    found running unlimited under a stale ``0/0`` entry left by a previous
    holder of their address. The controller shape is milder (one field, not a
    growing list) and strictly worse in one way: a randomized MAC that comes
    back throttled has no row anywhere explaining why.

    This function is inside the controller branch, so **a RouterOS venue
    never reaches it**: no new call, no new failure mode, no change to the
    ``/queue simple`` lifecycle. Removing queue rows at session end on
    RouterOS may well be right too, but it is a different change with a
    different blast radius and is deliberately not made here.

    ## Why it is not enough to do this where the disconnect happens

    It used to run only after a successful ``deauthorize_guest``, inside
    ``terminate`` -- which made the release conditional on this platform
    being the one that ended the session on the device. At a RADIUS-mode
    venue it is normally not: the NAS reports an Accounting-Stop, the
    session ends here, and ``issue_live_disconnect`` correctly declines to
    open a controller connection to remove an authorization that is already
    gone (``already_ended_on_device``). That early return took the release
    with it, so at such a venue the limit was set once and never removed --
    the ``/queue simple`` accumulation defect again, on a record that
    outlives the session and that nobody can find afterwards.

    So there are now three ways in, and none of them depends on us having
    ended the session: after a successful disconnect, after a *failed* one,
    and through ``release_rate_limit`` for the sessions the device ended
    itself.

    ## When the client has already left the controller's list

    The limit lives on the known-client record and survives the client
    going offline, but the Open API addresses clients through the
    *connected* list, so a release attempted after the device has left
    answers ``CLIENT_NOT_FOUND`` -- measured. That is why the release is
    issued at session end, at the moment the NAS reports the stop, while the
    device is usually still associated to the AP: it is the last reliable
    window, not a convenient one.

    When it is missed anyway, that outcome is recorded rather than
    swallowed. A ``CLIENT_NOT_FOUND`` gets its own log line and an
    ``ERROR`` row in the integration's own event feed, so a limit left
    standing has a record saying so and a MAC to look it up by -- which is
    precisely what the RouterOS version of this defect never had.

    Capability-gated and silent about a refusal it already knows the reason
    for: a venue connected with a hotspot-operator login cannot rate-limit at
    all, so it has no limit to clear, and logging that on every disconnect
    would be noise about a venue working exactly as documented.

    Never raises. It runs *after* the disconnect has been decided, on a path
    whose contract is that ending a session in this platform's records can
    never be blocked by the venue's equipment. A limit that could not be
    cleared is recorded in the integration's own feed by the failure path and
    logged here; it is not allowed to turn a successful disconnect into an
    exception.
    """
    capability = resolved.provider.client_capabilities(resolved.config).clear_rate_limit
    if not capability.supported:
        return
    try:
        await resolved.provider.clear_client_rate_limit(
            resolved.config, resolved.site_id, client_mac
        )
    except ProviderError as error:
        await _record_client_failure(
            session,
            resolved,
            action="clear_rate_limit",
            client_mac=client_mac,
            error=error,
        )
        logger.warning(
            # Two log keys, because they are two different situations and
            # only one of them is fixable by retrying. ``client_gone`` means
            # the window closed -- the device left the controller's list
            # before we got here -- and the limit is now stranded on a
            # record the Open API cannot address. Anything else is an
            # ordinary controller failure.
            "network_integration_controller_rate_limit_client_gone"
            if isinstance(error, ProviderClientNotFoundError)
            else "network_integration_controller_rate_limit_not_released",
            extra={
                "integration_id": str(resolved.integration.id),
                "error_code": getattr(error, "code", None),
                "rate_limit_left_standing": True,
            },
        )
    else:
        await _record_client_success(
            session, resolved, action="clear_rate_limit", client_mac=client_mac
        )


def _connection_config(
    integration: NetworkIntegration,
    credentials: dict[str, str],
    settings: object,
) -> ProviderConnectionConfig:
    """The same config ``NetworkIntegrationService._connection_config`` builds.

    Duplicated deliberately and narrowly: importing the service is the cycle
    this module exists to avoid, and the alternative -- moving the builder out
    to a shared module -- would touch the service's hottest path for the sake
    of one caller. Six fields, all read straight off the row.
    """
    return ProviderConnectionConfig(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_mode=integration.auth_mode,
        credentials=credentials,
        controller_id=integration.controller_id,
        tls_mode=integration.tls_mode or DEFAULT_CONTROLLER_TLS_MODE.value,
        tls_pinned_sha256=integration.tls_pinned_sha256,
        timeout_seconds=getattr(settings, "omada_api_timeout_seconds", 15.0),
    )


def build_controller_activity_reporting_lookup(session: AsyncSession):
    """Whether a venue can report that its guests are still using the
    network, bound to ``session``.

    Satisfies ``guest.service.VenueActivityReportingProtocol``, so the
    session-timeout sweep can stop measuring idleness at a venue where
    idleness is not measurable. See that function's ``activity_reporting``
    section for what goes wrong without it.

    ## What the answer is computed from

    ``last_activity_at`` -- the column the idle half of the sweep reads --
    is written by ``GuestService.record_usage`` and by nothing else, and
    ``record_usage`` has exactly two producers:

    * **RADIUS accounting Interim-Updates.** A venue with no controller
      integration at all is the MikroTik/RADIUS fleet, whose NAS sends
      them every 300 s (``Acct-Interim-Interval`` on the Access-Accept).
      That is why "no integration" answers ``True`` here rather than
      falling into the cautious branch: the premise is not unknown there,
      it is known to hold.
    * **The Omada Open-API usage sweep** (``usage_tasks``), which polls
      ``traffic_up_bytes``/``traffic_down_bytes`` off the controller's
      client table and pushes the delta through the same sink. Its
      selection is ``provider == omada AND auth_mode == openapi``, in SQL.

    So for a controller-managed venue there are **two** questions, and
    conflating them is what shipped:

    1. *Can this venue ever report?* -- the provider's ``client_stats``
       capability, computed from the integration's auth mode. A
       hotspot-operator (``legacy``) credential provably cannot read the
       client table (contract CR-002), so it answers no, and that is the
       venue where the idle sweep was firing on guests who were streaming.
    2. *Is anything reporting right now?* -- which ``client_capabilities``
       cannot answer, because it contacts nothing. It is computed from a
       column in the integration row, so at an ``openapi`` venue it says
       "yes" whether the controller is answering, unreachable, or switched
       off at the wall.

    Only the first was being asked, and its answer was being spent on the
    second. Measured 2026-09-18: zero Interim-Updates arrived from the
    controller that day and four of five expiries at that venue were still
    recorded as ``inactivity_timeout``. The guard read as working because
    the capability it consulted is always ``True`` there by construction.

    ## The signal for question 2, and why this one

    **Has anything moved ``last_activity_at`` at this venue inside
    ``VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES``** --
    ``GuestRepository.venue_activity_was_reported_since``.

    It is the right signal because it is the *same column the idle rule
    reads*. The sweep's idle branch measures ``now - last_activity_at``;
    the honest precondition for trusting that arithmetic is that something
    writes that column here, and this observes exactly that, with no
    inference in between. The alternatives were weaker. "Did the usage poll
    return rows" describes one of the two producers and says nothing about
    a RADIUS venue. "Did accounting arrive" is the same half-answer from
    the other side. A live probe of the controller was ruled out on sight:
    a console renders capabilities constantly, and a sweep is not where a
    network round trip per venue belongs.

    Note what it does **not** measure: how busy the guests are.
    ``record_usage`` bumps ``last_activity_at`` on every Interim-Update
    regardless of byte deltas, so a venue full of idle-but-connected guests
    still reports. See that repository method for why the comparison is
    against ``started_at`` rather than against the clock alone.

    ## What a venue with no controller integration gets: exactly today

    The whole MikroTik/RADIUS fleet short-circuits to ``True`` above,
    before any of this, and that is deliberate rather than an oversight to
    tidy up later. Their premise is documented as known to hold -- the NAS
    sends Interim-Updates every 300 s -- and the brief for this change was
    that MikroTik venues must not change behaviour. So the observation is
    applied only where the over-claim was: to controller-managed venues
    whose capability said yes.

    ## Why an unreadable integration answers ``False``

    A row whose credentials will not decrypt, or a provider this build does
    not know, cannot be polled either -- so no producer exists for it
    regardless of what its ``auth_mode`` column says. Answering ``True``
    there would resume ending sessions on evidence we do not have, which is
    the whole failure this closes. The absolute ``session_timeout_minutes``
    ceiling still applies to every one of those sessions, so nothing
    becomes immortal; it simply ends for the reason we can evidence.

    Read-only and cheap by design: at most two tenant-scoped reads -- the
    integration row, then one indexed ``EXISTS`` over this venue's sessions
    -- and no network call on either. That is what makes it safe to ask
    inside a sweep, and the sweep memoizes it per venue per run on top.
    """

    class _ActivityReporting:
        @staticmethod
        async def venue_reports_guest_activity(
            *,
            organization_id: uuid.UUID | None,
            location_id: uuid.UUID | None,
        ) -> bool:
            if organization_id is None or location_id is None:
                # Nothing to resolve a controller from. Not a controller
                # venue as far as this lookup can tell, so it is the
                # RADIUS answer, which is today's behaviour.
                return True
            repository = NetworkIntegrationRepository(session)
            integration = await repository.get_omada_integration_for_location(
                location_id=location_id, organization_id=organization_id
            )
            if integration is None:
                return True
            credentials: dict[str, str] = {}
            if integration.credentials_encrypted:
                try:
                    credentials = decrypt_credentials(
                        integration.credentials_encrypted, settings=get_settings()
                    )
                except NetworkIntegrationCredentialDecryptionError:
                    logger.warning(
                        "network_integration_activity_reporting_credentials_"
                        "unreadable",
                        extra={"integration_id": str(integration.id)},
                    )
                    return False
            else:
                # No credentials at all: nothing can poll this controller.
                return False
            try:
                provider = get_network_provider(integration.provider)
            except Exception:  # noqa: BLE001 -- an unknown provider cannot poll
                return False
            config = _connection_config(integration, credentials, get_settings())
            if not provider.client_capabilities(config).client_stats.supported:
                # Question 1: this venue can never report. No observation
                # needed, and none would be meaningful.
                return False
            # Question 2: it can -- but is it? Imported here rather than at
            # module scope for the reason this module's own docstring gives
            # about the direction of the guest edge.
            from app.domains.guest.constants import (  # noqa: PLC0415
                VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES,
            )
            from app.domains.guest.repository import GuestRepository  # noqa: PLC0415

            since = datetime.now(UTC) - timedelta(
                minutes=VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES
            )
            reported = await GuestRepository(session).venue_activity_was_reported_since(
                organization_id=organization_id,
                location_id=location_id,
                since=since,
            )
            if not reported:
                # Worth a line: the capability says this controller can be
                # polled and nothing has arrived from it in the window, which
                # is either a dead controller or a stopped poll, and both are
                # things an operator would want to know before wondering why
                # sessions now run to their full ceiling.
                logger.warning(
                    "network_integration_venue_reports_no_guest_activity",
                    extra={
                        "integration_id": str(integration.id),
                        "location_id": str(location_id),
                        "window_minutes": VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES,
                    },
                )
            return reported

    return _ActivityReporting()

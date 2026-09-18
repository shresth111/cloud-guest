"""Per-client controller writes for callers that cannot hold a
``NetworkIntegrationService``.

Two hooks live here -- ending one client's session, and setting or clearing
one client's speed limit -- and they share one tenant-scoped resolution.

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

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings

from .constants import DEFAULT_CONTROLLER_TLS_MODE
from .crypto import (
    NetworkIntegrationCredentialDecryptionError,
    decrypt_credentials,
)
from .exceptions import (
    ClientActionUnavailableError,
    LocationHasNoControllerError,
    NetworkIntegrationUrlRejectedError,
    ProviderError,
)
from .models import NetworkIntegration
from .providers import get_network_provider
from .providers.base import ProviderConnectionConfig
from .repository import NetworkIntegrationRepository
from .validators import normalize_client_mac

logger = logging.getLogger(__name__)

__all__ = [
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
            return await resolved.provider.set_client_rate_limit(
                resolved.config,
                resolved.site_id,
                _require_mac(client_mac),
                down_kbps=down_kbps,
                up_kbps=up_kbps,
            )

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
            return await resolved.provider.clear_client_rate_limit(
                resolved.config, resolved.site_id, _require_mac(client_mac)
            )

    return _SpeedHook()


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


def build_controller_session_terminator(session: AsyncSession):
    """A callable that ends one client's controller session, bound to
    ``session``.

    Returned rather than exported directly so the caller supplies the database
    session once, at wiring time, and the terminator's own signature stays
    free of it -- ``LiveSessionTerminator`` has no session and should not grow
    one.
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
            return bool(
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
            raise

    return terminate


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

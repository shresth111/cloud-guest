"""Live device-side push for a RouterOS API credential rotation.

## Why this exists

Master Console's Setup Script panel (``master.routers.tsx``'s ``onGenerate``)
mints a fresh random ``api_secret`` and immediately persists it via
``PUT /routers/{id}`` every time it runs against an already-provisioned
router -- not just on first-time issuance. Persisting alone only updates
this platform's own record of what the device's ``cloudguest-api`` RouterOS
user password *should* be; the device itself is only ever updated if an
admin separately copies the generated "API Access" script chunk and runs it
on the device in WinBox. Skip that manual step (or run it against the wrong
router, or lose network access to the device before getting to it) and the
two fall out of sync -- the platform then gets a real, honest
``Permission denied for user cloudguest-api`` straight from RouterOS on
every subsequent connection attempt, exactly the shape of the production
incident this module exists to close.

``RouterService.update_router`` uses ``DeviceCredentialRotatorProtocol``
to push the new password to the live device *before* ever persisting it,
whenever this is a genuine rotation (the router already has a working
host/username/secret on file) rather than first-time issuance (nothing to
rotate against yet). Either both the device and the DB end up on the new
secret, or neither does -- the old secret keeps working either way.

## Gateway transport (config-agent bridge retired)

The legacy SSH config-agent HTTP bridge
(``app.domains.network_config.router.apply_network_config_live``'s old
transport) is retired (router-fleet plan section A1). Live pushes now go
through the vendored ``wyfy_device_gateway`` over the WireGuard tunnel --
``execute_live_command`` runs ``/user set ... password=...`` over the
device's real SSH console, the same primitive the bridge used to wrap.
"""

from __future__ import annotations

import logging
from typing import Protocol

from .device_adapters import (
    DeviceLiveConnectionError,
    execute_live_command,
)

logger = logging.getLogger(__name__)


class DeviceCredentialRotationError(Exception):
    """Raised when a live password push to the device did not succeed --
    ``RouterService.update_router`` translates this into a real
    ``RouterLiveCredentialRotationFailedError`` rather than letting a raw
    gateway exception leak out of the service layer."""


class DeviceCredentialRotatorProtocol(Protocol):
    """The minimal surface ``RouterService`` needs to push a real password
    change to a device before trusting the new secret enough to persist
    it. ``old_password`` is what authenticates the push (the device still
    only knows its *current* password); ``new_password`` is what the
    device is told to set going forward."""

    async def rotate_password(
        self,
        *,
        host: str,
        username: str,
        old_password: str,
        new_password: str,
    ) -> None:
        """Raises :class:`DeviceCredentialRotationError` if the device
        could not be reached, authentication with ``old_password`` was
        rejected, or the push otherwise reports the change did not
        apply. Returns normally only once the device itself has
        confirmed the new password is live."""
        ...


class GatewayDeviceCredentialRotator:
    """Real implementation -- see module docstring. Stateless singleton
    wired by ``app.domains.router.dependencies``."""

    async def rotate_password(
        self,
        *,
        host: str,
        username: str,
        old_password: str,
        new_password: str,
    ) -> None:
        # RouterOS scripting quoting: the username/password values here are
        # platform-generated (API_ACCESS_USERNAME is a fixed constant;
        # generateApiSecret() produces an alphanumeric secret -- see
        # master.routers.tsx), never end-user free text, so a literal
        # double-quoted RouterOS string is safe without a general escaping
        # routine.
        script = f'/user set [find name="{username}"] password="{new_password}"\n'
        try:
            result = await execute_live_command(
                host=host,
                username=username,
                password=old_password,
                command=script,
            )
        except DeviceLiveConnectionError as exc:
            raise DeviceCredentialRotationError(
                f"could not reach the device: {exc.detail}"
            ) from exc

        if result.exit_status != 0:
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise DeviceCredentialRotationError(detail)


__all__ = [
    "DeviceCredentialRotationError",
    "DeviceCredentialRotatorProtocol",
    "GatewayDeviceCredentialRotator",
]

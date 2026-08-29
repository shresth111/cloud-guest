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


def _escape_routeros_string(value: str) -> str:
    """Escapes a value for safe interpolation inside a double-quoted
    RouterOS console string literal.

    RouterOS's scripting language treats ``\\`` as its escape character
    inside ``"..."`` literals, so ``\\`` must be escaped first (otherwise a
    literal backslash in the value would combine with whatever character
    follows it to form an unintended escape sequence), then the enclosing
    ``"`` delimiter itself. ``$`` also triggers RouterOS variable expansion
    inside a double-quoted string (e.g. ``$foo``), so it is escaped too --
    without this, a value like ``$RandomVariable`` would be substituted by
    the router's own scripting engine rather than treated as a literal
    password.

    This alone does not make arbitrary input safe to interpolate as a bare,
    unquoted RouterOS command fragment (e.g. breaking out via ``;`` after
    the closing quote) -- callers must still only ever place the escaped
    result *inside* a quoted literal, never concatenate it in as raw
    script. Defense in depth: this is the second of two independent layers
    guarding this value, the first being the strict charset allowlist on
    ``api_secret`` enforced by ``RouterCreateRequest``/``RouterUpdateRequest``
    (``app.domains.router.schemas``) -- this escaping exists so a
    compromise or future loosening of that schema-level allowlist still
    cannot break out of the RouterOS script this module builds."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


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
        # RouterOS scripting quoting: username/password are escaped before
        # interpolation into the double-quoted string literals below.
        # username is normally the fixed API_ACCESS_USERNAME constant and
        # new_password is normally a platform-generated alphanumeric secret
        # (see master.routers.tsx's generateApiSecret()), but api_secret is
        # also settable directly via PUT /routers/{id} as operator-supplied
        # free text (RouterUpdateRequest.api_secret) -- this escaping is
        # defense in depth so that path can never break out of the script
        # regardless of what the schema-level allowlist currently permits.
        safe_username = _escape_routeros_string(username)
        safe_password = _escape_routeros_string(new_password)
        script = f'/user set [find name="{safe_username}"] password="{safe_password}"\n'
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

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

## Bridge, not a direct connection

Reuses the exact same config-agent bridge
``app.domains.network_config.router.apply_network_config_live`` already
calls (see that module's own docstring for why: a plain ``http://``
endpoint with no CORS support that must be called server-to-server, not
from the browser). The bridge already accepts an arbitrary RouterOS script
string and runs it over the device's real SSH console after connecting
with the caller-supplied credentials -- a ``/user set ... password=...``
command is no different, from the bridge's point of view, than the
config-apply scripts it already runs.

The bridge's URL and shared secret were previously hardcoded module
constants (a live credential committed to source, duplicated here and in
``app.domains.network_config.router``). The bridge transport is retired
(router-fleet plan section A1); both values now come from Settings
(``config_agent_url``/``config_agent_secret``) and are injected by
``app.domains.router.dependencies``, which wires ``credential_rotator=None``
-- the documented persist-only fallback in
``RouterService._rotate_live_device_credential`` -- when the bridge is not
configured.
"""

from __future__ import annotations

import logging
from typing import Protocol

import httpx

logger = logging.getLogger(__name__)

_BRIDGE_TIMEOUT_SECONDS = 30.0


class DeviceCredentialRotationError(Exception):
    """Raised when a live password push to the device did not succeed --
    ``RouterService.update_router`` translates this into a real
    ``RouterLiveCredentialRotationFailedError`` rather than letting a raw
    ``httpx``/bridge exception leak out of the service layer."""


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
        rejected, or the bridge otherwise reports the change did not
        apply. Returns normally only once the device itself has
        confirmed the new password is live."""
        ...


class ConfigAgentBridgeCredentialRotator:
    """Real implementation -- see module docstring. Stateless apart from
    the bridge coordinates it is constructed with (never hardcode them --
    they come from Settings via ``app.domains.router.dependencies``)."""

    def __init__(self, *, agent_url: str, agent_secret: str) -> None:
        self._agent_url = agent_url
        self._agent_secret = agent_secret

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
            async with httpx.AsyncClient(timeout=_BRIDGE_TIMEOUT_SECONDS) as client:
                resp = await client.post(
                    self._agent_url,
                    headers={"X-Agent-Secret": self._agent_secret},
                    json={
                        "tunnel_ip": host,
                        "username": username,
                        "password": old_password,
                        "script": script,
                    },
                )
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPError as exc:
            raise DeviceCredentialRotationError(
                f"could not reach the config-agent bridge: {exc}"
            ) from exc

        if not result.get("applied"):
            detail = (
                result.get("detail") or result.get("error") or "bridge reported failure"
            )
            raise DeviceCredentialRotationError(str(detail))


__all__ = [
    "DeviceCredentialRotationError",
    "DeviceCredentialRotatorProtocol",
    "ConfigAgentBridgeCredentialRotator",
]

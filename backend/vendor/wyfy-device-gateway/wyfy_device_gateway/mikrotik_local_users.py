"""The router's own login accounts, over the RouterOS API (8728).

Used to give a router's local ``admin`` account a password the platform knows.

A password is never readable back from RouterOS, so the only proof that a
write landed is a fresh login with the new password. :func:`probe_login` is
that proof. It separates "wrong password" from "could not ask": treating an
unreachable router as a wrong password would make the platform overwrite a
password it has not actually tested.

Plain functions over an open ``api`` object, for the same reason as
``mikrotik_firewall``: they can be tested against a fake transport.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from librouteros.exceptions import LibRouterosError

_DENIED_MARKERS = ("invalid user name or password", "cannot log in")


class LoginProbeResult(StrEnum):
    ACCEPTED = "accepted"
    DENIED = "denied"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class LocalUser:
    name: str
    group: str
    disabled: bool


class LocalUserNotFoundError(Exception):
    """The named account does not exist on the device."""


def probe_login(connect: Callable[[], object]) -> LoginProbeResult:
    """Tries one login through ``connect`` and closes the connection.

    ``connect`` opens an API connection with the credentials under test and
    raises when it cannot. Accepted means a command really ran. Anything other
    than an explicit refusal from RouterOS counts as unreachable.
    """
    try:
        api = connect()
    except OSError:
        return LoginProbeResult.UNREACHABLE
    except LibRouterosError as exc:
        message = str(exc).lower()
        if any(marker in message for marker in _DENIED_MARKERS):
            return LoginProbeResult.DENIED
        return LoginProbeResult.UNREACHABLE
    # A login reply alone proves nothing. RouterOS before 6.43 answers the login
    # call used here with a challenge and no error, whatever the password was,
    # and only refuses at the next command. Measured on 6.42.12 CHR, where a
    # wrong password otherwise reads as accepted. Such a device cannot be
    # proven either way, so it reads as unreachable and nothing writes to it.
    try:
        tuple(api("/system/identity/print"))  # type: ignore[operator]
    except (LibRouterosError, OSError, EOFError):
        return LoginProbeResult.UNREACHABLE
    finally:
        with contextlib.suppress(LibRouterosError, OSError, EOFError):
            api.close()  # type: ignore[attr-defined]
    return LoginProbeResult.ACCEPTED


def list_users(api) -> list[LocalUser]:  # noqa: ANN001
    return [
        LocalUser(
            name=str(row.get("name", "")),
            group=str(row.get("group", "")),
            disabled=_truthy(row.get("disabled", False)),
        )
        for row in api("/user/print")
    ]


def set_password(api, *, username: str, new_password: str) -> None:  # noqa: ANN001
    """Sets one account's password. Finds the row first, because ``/user/set``
    with a ``.id`` that matches nothing is an error RouterOS words unhelpfully.
    """
    for row in api("/user/print"):
        if row.get("name") == username:
            tuple(api("/user/set", **{".id": row[".id"], "password": new_password}))
            return
    raise LocalUserNotFoundError(username)


def _truthy(value: object) -> bool:
    return value is True or str(value).lower() in {"true", "yes"}


__all__ = [
    "LocalUser",
    "LocalUserNotFoundError",
    "LoginProbeResult",
    "list_users",
    "probe_login",
    "set_password",
]

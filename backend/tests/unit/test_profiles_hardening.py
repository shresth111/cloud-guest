"""Unit tests for the clock/NTP and service-lockdown profiles.

These renderers emit text that will be pasted into a live router, so the
assertions here are deliberately about the *dangerous* properties rather than
the happy path: that a lockdown cannot disable the transport we manage the
device with, and that an empty allowlist never becomes a deny-all.
"""

from __future__ import annotations

import pytest

from app.domains.network_config.profiles.service_lockdown import (
    render_service_lockdown,
)
from app.domains.network_config.profiles.system_time import (
    DEFAULT_NTP_SERVERS,
    render_system_time,
)

# ---------------------------------------------------------------- system time


def test_system_time_sets_clock_before_ntp() -> None:
    lines = render_system_time()
    joined = "\n".join(lines)

    assert '/system clock set time-zone-name="Asia/Kolkata"' in joined
    assert "/system ntp client set enabled=yes" in joined
    assert ",".join(DEFAULT_NTP_SERVERS) in joined

    clock_at = next(i for i, line in enumerate(lines) if "/system clock set" in line)
    ntp_at = next(i for i, line in enumerate(lines) if "/system ntp client" in line)
    assert clock_at < ntp_at


def test_system_time_accepts_a_venue_timezone() -> None:
    lines = render_system_time(ntp_servers=["10.0.0.1"], time_zone="Europe/Lisbon")
    joined = "\n".join(lines)
    assert 'time-zone-name="Europe/Lisbon"' in joined
    assert 'servers="10.0.0.1"' in joined


def test_system_time_uses_more_than_one_pool_by_default() -> None:
    # A single unreachable server means the clock never sets at all, which
    # breaks certificate validation, RADIUS accounting and every timestamp we
    # collect back off the device.
    assert len(DEFAULT_NTP_SERVERS) > 1


def test_system_time_rejects_an_empty_server_list() -> None:
    with pytest.raises(ValueError, match="at least one NTP server"):
        render_system_time(ntp_servers=[])


def test_system_time_escapes_quotes() -> None:
    joined = "\n".join(render_system_time(time_zone='Bad"Zone'))
    assert r'time-zone-name="Bad\"Zone"' in joined


# ------------------------------------------------------------ service lockdown


def test_lockdown_disables_only_the_plaintext_services() -> None:
    joined = "\n".join(render_service_lockdown(allowed_addresses=["10.8.0.0/24"]))

    assert '/ip service set [find name="telnet"] disabled=yes' in joined
    assert '/ip service set [find name="ftp"] disabled=yes' in joined
    # The transports the platform manages the device with must survive.
    for keep in ("api", "ssh", "www"):
        assert f'[find name="{keep}"] disabled=yes' not in joined


def test_lockdown_allowlists_the_management_transports_without_disabling_them() -> None:
    joined = "\n".join(render_service_lockdown(allowed_addresses=["10.8.0.0/24"]))

    for keep in ("api", "ssh"):
        assert (
            f'/ip service set [find name="{keep}"] address="10.8.0.0/24" disabled=no'
            in joined
        )


def test_lockdown_joins_multiple_management_sources() -> None:
    joined = "\n".join(
        render_service_lockdown(allowed_addresses=["10.8.0.0/24", "203.0.113.7"])
    )
    assert 'address="10.8.0.0/24,203.0.113.7"' in joined


def test_empty_allowlist_never_becomes_a_deny_all() -> None:
    """The failure this guards is losing the router in a single line.

    RouterOS reads an empty ``address=`` as "no source may connect", so
    rendering one from an empty allowlist would lock out every operator and
    the platform at once.
    """
    lines = render_service_lockdown(allowed_addresses=[])
    joined = "\n".join(lines)

    assert "address=" not in joined
    # Still says so out loud, and still does the half that is safe.
    assert any("NOT applied" in line for line in lines)
    assert 'name="telnet"' in joined


def test_lockdown_refuses_to_disable_a_platform_transport() -> None:
    for service in ("api", "ssh", "www"):
        with pytest.raises(ValueError, match="Refusing to disable"):
            render_service_lockdown(
                allowed_addresses=["10.8.0.0/24"], disable_services=[service]
            )


def test_lockdown_rejects_an_unknown_service_name() -> None:
    # `set [find name="sshh"]` matches nothing and silently succeeds on a real
    # device, so a typo has to fail here or it never fails at all.
    with pytest.raises(ValueError, match="Unknown RouterOS service"):
        render_service_lockdown(disable_services=["sshh"])

    with pytest.raises(ValueError, match="Unknown RouterOS service"):
        render_service_lockdown(restrict_services=["winbocks"])


def test_lockdown_with_no_restrictions_still_disables() -> None:
    joined = "\n".join(render_service_lockdown(restrict_services=[]))
    assert 'name="telnet"' in joined
    assert "address=" not in joined


def test_winbox_is_not_restricted_by_default() -> None:
    # Field installers reach WinBox over the venue LAN; an allowlist that omits
    # that path turns a supported on-site workflow into a support call.
    joined = "\n".join(render_service_lockdown(allowed_addresses=["10.8.0.0/24"]))
    assert 'name="winbox"' not in joined


def test_lockdown_can_restrict_winbox_when_asked() -> None:
    joined = "\n".join(
        render_service_lockdown(
            allowed_addresses=["10.8.0.0/24"], restrict_services=["winbox"]
        )
    )
    assert '/ip service set [find name="winbox"] address="10.8.0.0/24"' in joined

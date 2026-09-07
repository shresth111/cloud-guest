"""``execute_raw_command`` -- the Master Console device console's transport.

The bug these tests pin down: the console ran every command over SSH (port
22), which is filtered on this fleet. ``/interface print`` against a healthy
router reported "connection attempt timed out" after asyncssh's own 10s
``connect_timeout``, while the identical credential over the RouterOS API
(8728) answered the same command in 57ms. See
``MikroTikAdapter.execute_raw_command``'s own docstring.

Two properties matter here, and the second matters more than the first:

1. A translatable command goes over the API, and no SSH connection is even
   attempted.
2. A command that CANNOT be translated faithfully is never approximated. A
   console that silently runs something other than what the operator typed
   is worse than one that refuses -- so every case the translator declines
   is asserted to fall through to SSH untouched, not to be reshaped into
   the nearest API sentence.
"""

from __future__ import annotations

from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikConnectionError,
    _console_command_to_api_sentence,
)


@pytest.fixture
def no_ssh(monkeypatch: pytest.MonkeyPatch):
    """Makes any SSH attempt an immediate, loud failure.

    Installed by default in the API-path tests: the whole point of the fix
    is that a translatable console command never touches port 22, and a
    test that merely *mocked* SSH successfully would still pass if the code
    silently kept using it."""
    import wyfy_device_gateway.mikrotik_adapter as module

    def _forbidden(*_args: Any, **_kwargs: Any):
        raise AssertionError("SSH must not be used for a translatable command")

    monkeypatch.setattr(module.asyncssh, "connect", _forbidden)


# ============================================================================
# The translator, in isolation
# ============================================================================


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/interface print", ("/interface/print", {})),
        ("/interface/print", ("/interface/print", {})),
        ("/ip firewall filter print", ("/ip/firewall/filter/print", {})),
        ("/system identity print", ("/system/identity/print", {})),
        ("/system reboot", ("/system/reboot", {})),
        (
            "/ip address add address=10.0.0.1/24 interface=ether2",
            (
                "/ip/address/add",
                {"address": "10.0.0.1/24", "interface": "ether2"},
            ),
        ),
        # Quoted values survive with their spaces, unquoted, exactly as the
        # API expects them -- a value is data, not more tokens.
        (
            '/system identity set name="Head Office"',
            ("/system/identity/set", {"name": "Head Office"}),
        ),
        # An empty value is a real RouterOS idiom (clearing a field), not a
        # malformed argument.
        ("/ip dns set servers=", ("/ip/dns/set", {"servers": ""})),
        # A scripting construct INSIDE a quoted value is data, not a
        # construct: `source=` takes script text, and the API takes it the
        # same way. Only a `:command` in *command* position is untranslatable.
        (
            '/system script add source=":log info hi"',
            ("/system/script/add", {"source": ":log info hi"}),
        ),
        ("  /interface   print  ", ("/interface/print", {})),
    ],
)
def test_translates_plain_commands(command: str, expected: tuple[str, dict[str, str]]):
    assert _console_command_to_api_sentence(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        # `where` is a CLI filter keyword, not a menu segment. Concatenating
        # it would send the nonexistent path /interface/print/where.
        "/interface print where running=yes",
        "/ip route print where dst-address=0.0.0.0/0",
        # `[find ...]` is a CLI sub-expression with no API-sentence form.
        '/ip service set [find name="ssh"] disabled=yes',
        # Scripting constructs.
        ":put [/system identity get name]",
        "/interface print; /ip address print",
        "/user print $var",
        # A menu path with no command word only opens a submenu on the CLI.
        "/interface",
        "/",
        # Not a command at all.
        "",
        "   ",
        "interface print",
        # A bare word after arguments have begun is a second command.
        "/ip address add address=10.0.0.1/24 print",
        # POSITIONAL CLI SYNTAX. `/user/set/admin` is not a real API path --
        # the API names the target with a `.id`/`numbers` word, not a path
        # segment. The naive translation would have issued a sentence the
        # operator never typed, so this must fall through to SSH.
        "/user set admin password=hunter2",
        "/interface monitor-traffic ether1",
        "/ip firewall filter remove 3",
        # A verb that is not the last word: another shape of the same thing.
        "/system script print run",
        # No verb at all -- a bare menu path with extra segments.
        "/interface ethernet switch",
        # Unbalanced quotes: let SSH's own parser have an opinion, not us.
        '/system identity set name="unterminated',
    ],
)
def test_refuses_to_translate_what_it_cannot_express(command: str):
    assert _console_command_to_api_sentence(command) is None


# ============================================================================
# The adapter: translatable commands run over the API
# ============================================================================


@pytest.mark.asyncio
async def test_interface_print_runs_over_api_not_ssh(
    patch_connect, mikrotik_creds, no_ssh
):
    """The exact command from the incident."""
    api = FakeRouterOSApi(
        command_replies={
            "/interface/print": [
                {".id": "*1", "name": "ether1", "type": "ether", "running": "true"},
                {".id": "*2", "name": "bridge-guest", "type": "bridge"},
            ]
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().execute_raw_command(
        mikrotik_creds, command="/interface print"
    )

    assert api.command_calls == [("/interface/print", {})]
    assert result.exit_status == 0
    assert result.stderr == ""
    assert result.command == "/interface print"
    assert result.stdout.splitlines() == [
        "  0 .id=*1 name=ether1 running=true type=ether",
        "  1 .id=*2 name=bridge-guest type=bridge",
    ]
    assert api.closed


@pytest.mark.asyncio
async def test_arguments_are_passed_through_as_api_words(
    patch_connect, mikrotik_creds, no_ssh
):
    api = FakeRouterOSApi(command_replies={"/ip/address/add": []})
    patch_connect(api)

    await MikroTikAdapter().execute_raw_command(
        mikrotik_creds, command="/ip address add address=10.0.0.1/24 interface=ether2"
    )

    assert api.command_calls == [
        ("/ip/address/add", {"address": "10.0.0.1/24", "interface": "ether2"})
    ]


@pytest.mark.asyncio
async def test_empty_reply_is_success_with_empty_output(
    patch_connect, mikrotik_creds, no_ssh
):
    api = FakeRouterOSApi(command_replies={"/system/reboot": []})
    patch_connect(api)

    result = await MikroTikAdapter().execute_raw_command(
        mikrotik_creds, command="/system reboot"
    )

    assert (result.stdout, result.stderr, result.exit_status) == ("", "", 0)


@pytest.mark.asyncio
async def test_device_side_rejection_is_a_result_not_an_exception(
    patch_connect, mikrotik_creds, no_ssh
):
    """A typo in a console is a result with a non-zero status -- the same
    contract the SSH path had (``RawCommandResult``'s own docstring), and
    the reason an operator's mistyped command must not become a 500."""
    api = FakeRouterOSApi(
        raise_on_command={
            "/inteface/print": LibRouterosError("no such command prefix")
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().execute_raw_command(
        mikrotik_creds, command="/inteface print"
    )

    assert result.exit_status == 1
    assert result.stderr == "no such command prefix"
    assert result.stdout == ""
    assert api.closed


@pytest.mark.asyncio
async def test_connection_failure_still_raises(patch_connect, mikrotik_creds, no_ssh):
    """A transport failure is NOT a command result -- the caller
    (``ProvisioningEngineService.execute_console_command``) distinguishes
    the two, and only the connection error gets tunnel-state enrichment."""
    patch_connect(OSError("connection refused"))

    with pytest.raises(MikroTikConnectionError) as excinfo:
        await MikroTikAdapter().execute_raw_command(
            mikrotik_creds, command="/interface print"
        )

    assert excinfo.value.host == mikrotik_creds.host


# ============================================================================
# The adapter: untranslatable commands still use SSH, and say so on failure
# ============================================================================


@pytest.mark.asyncio
async def test_untranslatable_command_falls_back_to_ssh(
    monkeypatch: pytest.MonkeyPatch, mikrotik_creds
):
    import wyfy_device_gateway.mikrotik_adapter as module

    ran: list[str] = []

    class _Result:
        stdout = "ok"
        stderr = ""
        exit_status = 0

    class _Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def run(self, command: str, check: bool = False):
            ran.append(command)
            return _Result()

    monkeypatch.setattr(module.asyncssh, "connect", lambda *a, **k: _Conn())

    command = '/ip service set [find name="ssh"] disabled=yes'
    result = await MikroTikAdapter().execute_raw_command(
        mikrotik_creds, command=command
    )

    # Sent verbatim -- never reshaped into "the nearest API sentence".
    assert ran == [command]
    assert result.stdout == "ok"
    assert result.exit_status == 0


@pytest.mark.asyncio
async def test_ssh_fallback_failure_names_the_transport_and_port(
    monkeypatch: pytest.MonkeyPatch, mikrotik_creds
):
    """The original bug's second half: an operator saw a bare "connection
    attempt timed out" with no way to tell that the platform had dialled a
    port their fleet filters. The error now says which one."""
    import wyfy_device_gateway.mikrotik_adapter as module

    def _timeout(*_args: Any, **_kwargs: Any):
        raise TimeoutError

    monkeypatch.setattr(module.asyncssh, "connect", _timeout)

    with pytest.raises(MikroTikConnectionError) as excinfo:
        await MikroTikAdapter().execute_raw_command(
            mikrotik_creds, command=":put [/system identity get name]"
        )

    detail = excinfo.value.detail
    assert "connection attempt timed out" in detail
    assert "over SSH, port 22" in detail
    assert "8728" in detail

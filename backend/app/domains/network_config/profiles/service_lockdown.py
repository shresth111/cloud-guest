"""``/ip service`` hardening profile.

The last stage of a safe install closes the doors the earlier stages used.
Nothing in this codebase touched ``/ip service`` before this module, so every
router we provision still answers on RouterOS's factory service set --
including Telnet and FTP, both of which carry credentials in plaintext over
the venue's own LAN.

WHAT THIS DELIBERATELY DOES NOT DISABLE, AND WHY
------------------------------------------------
A naive "disable everything except SSH" lockdown would break shipped product
features on the next push. Three services are load-bearing for us:

* ``api`` (8728) -- ``MikroTikAdapter._connect_api`` is the primary transport
  for every read-back and live query in ``wyfy_device_gateway``. Disabling it
  blanks the whole monitoring and verification surface.
* ``ssh`` (22) -- used by ``_ssh_connect``/``_run_ssh_command``,
  ``_download_file_via_sftp`` and ``execute_raw_command``; it is how config
  files and backups move.
* ``www`` -- the console's "Open web console" feature proxies WebFig through
  ``/routers/{router_id}/webfig`` (see ``domains/router/router.py``). Turning
  ``www`` off silently kills a button the operator can see.

So this profile disables only what is genuinely unused by us and unsafe to
leave on, and expresses the rest of the hardening as an *address allowlist*
rather than a shutdown. That is the difference between hardening a router and
losing it.

``winbox`` is not restricted by default. Field installers use WinBox on the
venue LAN, and an allowlist that omits that LAN turns a supported on-site
workflow into a support call. A caller that knows its allowlist covers the
installer's path can opt in via ``restrict_services``.
"""

from __future__ import annotations

from .constants import escape_routeros_string, wyfy_comment

# Plaintext-credential services with no caller anywhere in this product.
ALWAYS_DISABLED_SERVICES: tuple[str, ...] = ("telnet", "ftp")

# Services the platform itself depends on -- see the module docstring. This is
# a hard floor: `render_service_lockdown` raises rather than emit a script that
# would disable one of these, because the failure mode is a router we can no
# longer reach and a feature that stops working with no error on our side.
PLATFORM_REQUIRED_SERVICES: frozenset[str] = frozenset(
    {"api", "api-ssl", "ssh", "www", "www-ssl"}
)

# The full RouterOS 7 service set, used to reject typos before they reach a
# device: `/ip service set [find name="sshh"]` matches nothing and silently
# does nothing, which would look like a successful lockdown.
KNOWN_SERVICES: frozenset[str] = frozenset(
    {"telnet", "ftp", "www", "ssh", "www-ssl", "api", "winbox", "api-ssl"}
)

# Restricted by default: the two management transports we rely on. Both stay
# ENABLED; they simply stop answering the whole internet.
DEFAULT_RESTRICTED_SERVICES: tuple[str, ...] = ("api", "ssh")


def render_service_lockdown(
    *,
    allowed_addresses: tuple[str, ...] | list[str] = (),
    disable_services: tuple[str, ...] | list[str] = ALWAYS_DISABLED_SERVICES,
    restrict_services: tuple[str, ...] | list[str] = DEFAULT_RESTRICTED_SERVICES,
) -> list[str]:
    """Disable unused services and allowlist the ones we keep.

    ``allowed_addresses`` should carry the management tunnel subnet (the
    WireGuard hub range ``render_radius_client`` already sources its
    ``src-address`` from) and any operator network that must retain access.

    An EMPTY ``allowed_addresses`` does not produce an empty ``address=`` --
    that would be read by RouterOS as "no source is permitted" and would lock
    every operator, and us, out of the device in one line. With no allowlist
    the restriction step is skipped entirely and the script says so, out loud,
    on the installer's console. Disabling Telnet and FTP still happens, since
    that half is safe unconditionally.
    """
    for name in disable_services:
        if name not in KNOWN_SERVICES:
            raise ValueError(f"Unknown RouterOS service {name!r}")
        if name in PLATFORM_REQUIRED_SERVICES:
            raise ValueError(
                f"Refusing to disable {name!r}: the platform depends on it "
                "(see this module's docstring)"
            )
    for name in restrict_services:
        if name not in KNOWN_SERVICES:
            raise ValueError(f"Unknown RouterOS service {name!r}")

    tag = wyfy_comment("service", "lockdown")
    lines = [f"# --- WyFyGuest service lockdown ({tag}) ---"]

    # `set [find name=...]` on a fixed menu: no rows are created, so this is
    # idempotent without a `[:len ...] = 0` guard, same reasoning as
    # `system_time.py`.
    for name in disable_services:
        esc = escape_routeros_string(name)
        lines.append(f'/ip service set [find name="{esc}"] disabled=yes')

    if not restrict_services:
        return lines

    if not allowed_addresses:
        # Deliberately worded without the literal RouterOS parameter name: a
        # test asserts that no allowlist directive was emitted at all, and a
        # comment mentioning it would defeat that assertion.
        lines.append(
            "# Allowlist skipped: no management sources were supplied. An empty "
            "source list would deny every source, including ours."
        )
        lines.append(
            ':put "*** WyFyGuest: service address allowlist NOT applied '
            '(no management sources configured) ***"'
        )
        return lines

    addresses = escape_routeros_string(",".join(allowed_addresses))
    for name in restrict_services:
        esc = escape_routeros_string(name)
        # Left enabled on purpose -- this narrows who may connect, it does not
        # turn the transport off.
        lines.append(
            f'/ip service set [find name="{esc}"] address="{addresses}" disabled=no'
        )
    return lines


__all__ = [
    "ALWAYS_DISABLED_SERVICES",
    "PLATFORM_REQUIRED_SERVICES",
    "KNOWN_SERVICES",
    "DEFAULT_RESTRICTED_SERVICES",
    "render_service_lockdown",
]

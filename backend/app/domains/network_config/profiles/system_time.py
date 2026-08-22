"""Clock and NTP profile renderers.

Nothing in this codebase set the router's clock before this module. That is a
small omission with disproportionate consequences: a MikroTik with no battery
boots to 1970, and until it learns the real time,

* every HTTPS call the router makes fails certificate validation -- which
  includes ``/tool fetch`` to our own API, the transport
  ``wan/renderers.py``-era bootstrap and ``render_agent_heartbeat_scheduler``
  both depend on (see ``renderers.py``'s ``_require_https``: RouterOS 7
  verifies certificates by default and no ``check-certificate=no`` override is
  rendered anywhere, deliberately),
* RADIUS exchanges and hotspot session accounting are stamped with a
  meaningless clock, so a guest's session length and data cap are computed
  against 1970, and
* every log line and ``RouterEvent`` timestamp we collect back off the device
  is unusable for support.

RouterOS 7 syntax only. That is not a shortcut: ``planner/compatibility.py``'s
``_check_routeros_version`` already BLOCKS provisioning for anything below
major 7, so a v6 branch here would be unreachable code guarding against a
device the planner refuses to touch.
"""

from __future__ import annotations

from .constants import escape_routeros_string, wyfy_comment

# Where the router asks for the time. Two pools, not one -- an installer on a
# venue's own uplink may find the first blocked, and a single unreachable
# server means the clock never sets at all rather than degrading.
DEFAULT_NTP_SERVERS: tuple[str, ...] = ("pool.ntp.org", "time.cloudflare.com")

# India is the only market this product ships in today (see the marketing
# site's own locale set and the RADIUS/hotspot copy), so it is the honest
# default rather than UTC. Any caller with a real venue timezone should pass
# it; this value exists so a router is never left on a wrong-but-silent clock.
DEFAULT_TIME_ZONE = "Asia/Kolkata"


def render_system_time(
    *,
    ntp_servers: tuple[str, ...] | list[str] = DEFAULT_NTP_SERVERS,
    time_zone: str = DEFAULT_TIME_ZONE,
) -> list[str]:
    """Enable the NTP client and pin the timezone.

    ``/system ntp client set`` and ``/system clock set`` are both *set*
    operations on singleton menus -- there is no row to find, no duplicate to
    create, and re-running is inherently a no-op-if-unchanged. So unlike the
    ``add``-based renderers in this package, these lines need no
    ``:if ([:len [... find ...]] = 0)`` guard to be idempotent; the guard
    pattern exists to stop duplicate rows, and singletons cannot have any.

    The verification read-back is ``/system clock`` -- already captured as the
    ``system_clock`` section in the gateway's ``READ_ONLY_SECTION_PATHS`` --
    plus ``system_ntp_client``, added alongside this module.
    """
    if not ntp_servers:
        raise ValueError("render_system_time requires at least one NTP server")

    servers = escape_routeros_string(",".join(ntp_servers))
    zone = escape_routeros_string(time_zone)
    tag = wyfy_comment("system", "time")

    return [
        f"# --- WyFyGuest clock and NTP ({tag}) ---",
        # Timezone first. NTP gives the router an absolute instant; the
        # timezone is what makes every log line and hotspot session a support
        # engineer reads afterwards match the wall clock at the venue.
        f'/system clock set time-zone-name="{zone}"',
        f'/system ntp client set enabled=yes servers="{servers}"',
    ]


__all__ = [
    "DEFAULT_NTP_SERVERS",
    "DEFAULT_TIME_ZONE",
    "render_system_time",
]

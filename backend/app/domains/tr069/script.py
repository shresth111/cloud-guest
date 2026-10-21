"""The MikroTik ``/tr069-client`` script (API_CONTRACT §5).

A new provisioning step in this domain; the existing setup-script generator
is not touched. Every interpolated value is RouterOS-quoted: ``\\``, ``"``
and ``$`` are escaped (``$`` would otherwise start variable substitution
inside a double-quoted RouterOS string), and newlines are refused.
"""

from __future__ import annotations

from datetime import UTC, datetime

CA_URL = "https://letsencrypt.org/certs/isrgrootx1.pem"
CA_NAME = "wyfy-acs-root"


def ros_quote(value: str) -> str:
    """A RouterOS double-quoted string literal."""
    text = str(value)
    if any(ch in text for ch in "\r\n\x00"):
        raise ValueError("RouterOS string values cannot contain newlines")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def render_tr069_script(
    *,
    acs_url: str,
    username: str,
    password: str,
    interval_s: int,
    enabled: bool,
    now: datetime | None = None,
) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    enabled_word = "yes" if enabled else "no"
    lines = [
        "# Wyfy Guest Network: TR-069 management",
        "# Paste into a RouterOS terminal. Needs the tr069-client package.",
        ':if ([:len [/system package find name="tr069-client"]] = 0) do={ '
        ':error "WYFY-TR069: install the tr069-client package for this RouterOS '
        'version and architecture, reboot, then paste this again" }',
        f":if ([:len [/certificate find name={ros_quote(CA_NAME)}]] = 0) do={{ "
        f"/tool fetch url={ros_quote(CA_URL)} dst-path={ros_quote(CA_NAME + '.pem')}; "
        ":delay 2s; "
        f"/certificate import file-name={ros_quote(CA_NAME + '.pem')} "
        f'name={ros_quote(CA_NAME)} passphrase="" }}',
        f":if ([:len [/certificate find name={ros_quote(CA_NAME)}]] = 0) do={{ "
        ':error "WYFY-TR069: could not import the ACS root certificate" }',
        "/tr069-client set "
        f"acs-url={ros_quote(acs_url)} "
        f"username={ros_quote(username)} "
        f"password={ros_quote(password)} "
        "periodic-inform-enabled=yes "
        f"periodic-inform-interval={int(interval_s)}s "
        f"enabled={enabled_word}",
    ]
    if enabled:
        lines += [
            ":delay 10s",
            ":local st [/tr069-client get status]",
            ':if ($st = "running") do={ :put "WYFY-TR069: PASS (status=running)" } '
            'else={ :error ("WYFY-TR069: status=" . $st . " " . '
            "[/tr069-client get last-session-error]) }",
        ]
    else:
        lines.append(':put "WYFY-TR069: management disabled for this location"')
    lines.append(f"/system note set note={ros_quote('wyfy-tr069 ' + stamp)}")
    return "\n".join(lines) + "\n"

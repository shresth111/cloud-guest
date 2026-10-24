# ruff: noqa: E501 -- RouterOS script text is kept verbatim
"""The MikroTik ``/tr069-client`` script (API_CONTRACT §5), with the
``tr069-client`` package installed by the script itself when it is missing.

This is a provisioning step of our own domain; the existing setup-script
generator is not touched. The partner app appends this block to the END of
the main setup script when the location's TR-069 is on, and the location card
still offers it on its own for routers that are already set up.

Shape (all RouterOS 6.x and 7.x):

    /system script add name="wyfy-tr069-config" source="..."    the config
    /system script add name="wyfy-tr069-afterboot" source="..." runs config after
                                                                a package reboot
    /system script add name="wyfy-tr069-install" source="..."   the decision
    /system script run wyfy-tr069-install

Every line typed at the console is one self-contained statement with no
variables: the console runs each pasted line as its own program, so locals
would not survive. All logic lives inside the script sources, where locals
and multi-statement blocks are ordinary RouterOS. That also keeps the block
clean under the setup panel's chunk validator.

The install script:
1. Parses ``/system resource get version`` ("7.16.2 (stable)" -> "7.16.2")
   and ``architecture-name``. Any major version other than 6 or 7, and any
   architecture outside ``ARCH_SUFFIX``, prints a clear message and changes
   nothing. There is no reboot.
2. tr069-client installed and enabled: imports ISRG Root X1 if no certificate
   with that common name exists, then runs the config. No reboot.
3. Otherwise: imports the CA (an internet failure stops here, no reboot), then
   either re-enables a disabled package, or downloads
   ``PACKAGE_URL_TEMPLATE`` and checks it exists with a sane size (any failure
   stops here, no reboot). It then registers the one-shot start-up scheduler
   that runs the config after the reboot and removes itself, prints
   "router will reboot in 10s to install TR-069", and reboots in the
   BACKGROUND after 10 s, so anything pasted after this block still finishes.

Safe to paste twice: every script and scheduler entry is removed by name and
re-added, the CA and the package are guarded, and the download overwrites
the same file.

Interpolated values are RouterOS-quoted (``\\``, ``"``, ``$`` escaped;
newlines refused). The script sources are quoted once more as a whole, with
real newlines written as ``\\n``.
"""

from __future__ import annotations

from datetime import UTC, datetime

CA_URL = "https://letsencrypt.org/certs/isrgrootx1.pem"
CA_FILE = "wyfy-acs-root.pem"
#: The ACS (acs-staging / acs) leaf chains to ISRG Root X1. Matched by common
#: name, not by our own name: RouterOS 6 `/certificate import` has no `name=`,
#: and a root someone imported earlier counts.
CA_COMMON_NAME = "ISRG Root X1"

CONFIG_SCRIPT = "wyfy-tr069-config"
AFTERBOOT_SCRIPT = "wyfy-tr069-afterboot"
INSTALL_SCRIPT = "wyfy-tr069-install"
BOOT_SCHEDULER = "wyfy-tr069-boot"

#: RouterOS extra-package download layout, verified 2026-10-24 against
#: download.mikrotik.com with HTTP HEAD (and the npk magic 1ef1d0ba) for
#: 6.48.6, 6.49.17, 6.49.23, 7.1, 7.12, 7.16.2, 7.23.8 and 7.25. Both major
#: versions use the same per-package files: no all_packages zip is needed.
PACKAGE_URL_TEMPLATE = (
    "https://download.mikrotik.com/routeros/{ver}/tr069-client-{ver}{suffix}.npk"
)
#: `architecture-name` -> file-name suffix. x86 (and CHR, which reports
#: x86_64) ship WITHOUT a suffix; "-x86" is a 404 on every version checked.
#: Every size seen was 118-279 KB, so MIN/MAX below leave a wide margin.
ARCH_SUFFIX: dict[str, str] = {
    "arm": "-arm",
    "arm64": "-arm64",
    "mipsbe": "-mipsbe",
    "mmips": "-mmips",
    "smips": "-smips",
    "ppc": "-ppc",
    "tile": "-tile",
    "x86": "",
    "x86_64": "",
}
SUPPORTED_MAJORS = ("6", "7")
PACKAGE_MIN_BYTES = 50_000
PACKAGE_MAX_BYTES = 3_000_000
REBOOT_DELAY_S = 10


def ros_quote(value: str) -> str:
    """A RouterOS double-quoted string literal."""
    text = str(value)
    if any(ch in text for ch in "\r\n\x00"):
        raise ValueError("RouterOS string values cannot contain newlines")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def ros_source(lines: list[str]) -> str:
    """A whole multi-line script as one RouterOS string literal: each line is
    quoted as text and the line breaks are written as ``\\n``."""
    return '"' + "\\n".join(ros_quote(line)[1:-1] for line in lines) + '"'


def router_version(raw: str) -> str:
    """Python twin of the script's parse: "7.16.2 (stable)" -> "7.16.2"."""
    return raw.split(" ", 1)[0].strip()


def package_url(raw_version: str, arch: str) -> str | None:
    """Python twin of the script's URL choice; None = unsupported (no reboot)."""
    ver = router_version(raw_version)
    if ver[:1] not in SUPPORTED_MAJORS or arch not in ARCH_SUFFIX:
        return None
    return PACKAGE_URL_TEMPLATE.format(ver=ver, suffix=ARCH_SUFFIX[arch])


def _config_lines(
    *, acs_url: str, username: str, password: str, interval_s: int, enabled: bool
) -> list[str]:
    word = "yes" if enabled else "no"
    lines = [
        "/tr069-client set "
        f"acs-url={ros_quote(acs_url)} "
        f"username={ros_quote(username)} "
        f"password={ros_quote(password)} "
        "periodic-inform-enabled=yes "
        f"periodic-inform-interval={int(interval_s)}s "
        f"enabled={word}",
    ]
    if enabled:
        lines += [
            ":delay 10s",
            ":do {",
            "  :local st [/tr069-client get status]",
            '  :log info ("WYFY-TR069: tr069-client status=" . $st)',
            '  :put ("WYFY-TR069: tr069-client status=" . $st . " (running = talking to the ACS)")',
            '} on-error={ :log warning "WYFY-TR069: could not read tr069-client status" }',
        ]
    else:
        lines.append(':put "WYFY-TR069: management disabled for this location"')
    return lines


def _ca_lines() -> list[str]:
    """Import ISRG Root X1 only if no certificate has that common name."""
    return [
        ":local caOk true",
        f':if ([:len [/certificate find where common-name="{CA_COMMON_NAME}"]] = 0) do={{',
        "  :do {",
        f'    /tool fetch url="{CA_URL}" dst-path="{CA_FILE}"',
        "    :delay 2s",
        f'    /certificate import file-name="{CA_FILE}" passphrase=""',
        "  } on-error={ :set caOk false }",
        f'  :if ([:len [/certificate find where common-name="{CA_COMMON_NAME}"]] = 0) do={{ :set caOk false }}',
        "}",
    ]


def _install_lines(*, enabled: bool) -> list[str]:
    arch_ifs = [
        f':if ($arch = "{arch}") do={{ :set suffix "{suffix}"; :set known true }}'
        for arch, suffix in ARCH_SUFFIX.items()
    ]
    majors = " or ".join(f'($major = "{m}")' for m in SUPPORTED_MAJORS)
    head = [
        ":local raw [/system resource get version]",
        ':local sp [:find $raw " "]',
        ":local ver $raw",
        ':if ([:typeof $sp] = "num") do={ :set ver [:pick $raw 0 $sp] }',
        ":local major [:pick $ver 0 1]",
        ":local arch [/system resource get architecture-name]",
        ':local pkg [/system package find where name="tr069-client"]',
        ':local state "missing"',
        ':if ([:len $pkg] > 0) do={ :set state "installed" }',
        ':if ($state = "installed") do={ :if ([/system package get $pkg disabled] = true) do={ :set state "disabled" } }',
    ]
    if not enabled:
        return head + [
            ':if ($state = "installed") do={',
            f"  /system script run {CONFIG_SCRIPT}",
            f'  /system script remove [find where name="{CONFIG_SCRIPT}"]',
            "} else={",
            '  :put "WYFY-TR069: management is off for this location and tr069-client is not installed; nothing to do"',
            "}",
        ]
    return head + [
        ':if ($state = "installed") do={',
        *("  " + line for line in _ca_lines()),
        '  :if ($caOk) do={ :put "WYFY-TR069: tr069-client present, applying config" } else={ :put "WYFY-TR069: WARNING could not import the ISRG Root X1 certificate (check DNS and internet); applying config, but HTTPS to the ACS fails until it is imported" }',
        f"  /system script run {CONFIG_SCRIPT}",
        f'  /system script remove [find where name="{CONFIG_SCRIPT}"]',
        f'  /system script remove [find where name="{AFTERBOOT_SCRIPT}"]',
        "} else={",
        "  :local ok true",
        f'  :if (!({majors})) do={{ :set ok false; :put ("WYFY-TR069: RouterOS " . $ver . " is not supported (6.x and 7.x only). Nothing changed, no reboot.") }}',
        '  :local suffix ""',
        "  :local known false",
        *("  " + line for line in arch_ifs),
        '  :if ($ok and !$known) do={ :set ok false; :put ("WYFY-TR069: architecture " . $arch . " is not supported. Nothing changed, no reboot.") }',
        "  :if ($ok) do={",
        *("    " + line for line in _ca_lines()),
        '    :if (!$caOk) do={ :set ok false; :put "WYFY-TR069: ERROR could not download/import the ISRG Root X1 certificate (check DNS and internet). Nothing changed, no reboot." }',
        "  }",
        '  :if ($ok and ($state = "disabled")) do={',
        "    /system package enable tr069-client",
        '    :put "WYFY-TR069: tr069-client was disabled; enabled it"',
        "  }",
        '  :if ($ok and ($state = "missing")) do={',
        '    :local fn ("tr069-client-" . $ver . $suffix . ".npk")',
        '    :local url ("https://download.mikrotik.com/routeros/" . $ver . "/" . $fn)',
        '    :put ("WYFY-TR069: downloading " . $url)',
        '    :do { /tool fetch url=$url dst-path=$fn } on-error={ :set ok false; :put ("WYFY-TR069: ERROR could not download " . $url . " (check DNS and internet). Nothing changed, no reboot.") }',
        "    :if ($ok) do={",
        "      :delay 2s",
        "      :local f [/file find where name=$fn]",
        '      :if ([:len $f] = 0) do={ :set ok false; :put ("WYFY-TR069: ERROR " . $fn . " is not on the router after the download. No reboot.") }',
        "      :if ($ok) do={",
        "        :local sz [/file get $f size]",
        f'        :if (($sz < {PACKAGE_MIN_BYTES}) or ($sz > {PACKAGE_MAX_BYTES})) do={{ :set ok false; /file remove $f; :put ("WYFY-TR069: ERROR " . $fn . " has an unexpected size (" . $sz . " bytes); removed it. No reboot.") }}',
        "      }",
        "    }",
        "  }",
        "  :if ($ok) do={",
        f'    /system scheduler remove [find where name="{BOOT_SCHEDULER}"]',
        f'    /system scheduler add name="{BOOT_SCHEDULER}" start-time=startup on-event="/system script run {AFTERBOOT_SCRIPT}"',
        f'    :put "WYFY-TR069: router will reboot in {REBOOT_DELAY_S}s to install TR-069. After it is back, the TR-069 settings apply by themselves."',
        f'    :log warning "WYFY-TR069: rebooting in {REBOOT_DELAY_S}s to install tr069-client"',
        f'    :execute ":delay {REBOOT_DELAY_S}s; /system reboot"',
        "  }",
        "}",
    ]


def _afterboot_lines() -> list[str]:
    return [
        ":delay 20s",
        ':if ([:len [/system package find where name="tr069-client" and disabled=no]] > 0) do={',
        f"  /system script run {CONFIG_SCRIPT}",
        '  :log info "WYFY-TR069: tr069-client installed; TR-069 settings applied"',
        "} else={",
        '  :log error "WYFY-TR069: tr069-client is still not installed after the reboot; see /log for package errors"',
        "}",
        f'/system script remove [find where name="{CONFIG_SCRIPT}"]',
        f'/system scheduler remove [find where name="{BOOT_SCHEDULER}"]',
        f'/system script remove [find where name="{AFTERBOOT_SCRIPT}"]',
    ]


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
    config = _config_lines(
        acs_url=acs_url,
        username=username,
        password=password,
        interval_s=interval_s,
        enabled=enabled,
    )
    lines = [
        f"# Wyfy Guest Network: TR-069 management (generated {stamp})",
        "# RouterOS 6.x / 7.x. Installs the tr069-client package if it is missing;",
        "# in that case the router REBOOTS at the very end and applies these",
        "# settings by itself once it is back. Safe to paste twice.",
    ]
    for name, body in (
        (CONFIG_SCRIPT, config),
        (AFTERBOOT_SCRIPT, _afterboot_lines()),
        (INSTALL_SCRIPT, _install_lines(enabled=enabled)),
    ):
        lines += [
            f'/system script remove [find where name="{name}"]',
            f'/system script add name="{name}" dont-require-permissions=yes source={ros_source(body)}',
        ]
    lines += [
        f"/system script run {INSTALL_SCRIPT}",
        f'/system script remove [find where name="{INSTALL_SCRIPT}"]',
    ]
    return "\n".join(lines) + "\n"

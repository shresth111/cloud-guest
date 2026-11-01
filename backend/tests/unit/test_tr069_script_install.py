# ruff: noqa: E501 -- RouterOS text is kept verbatim
"""The TR-069 RouterOS script installs tr069-client itself (founder ask,
2026-10-24: "saare version ke according").

The router does the version/arch decision at run time; ``package_url`` is its
Python twin and is pinned here against the download URLs verified on
download.mikrotik.com (HTTP HEAD + npk magic, 2026-10-24). The generated text
is checked for every architecture, the skip path (package present: config,
no reboot), the fail paths (unsupported version/arch, no internet, bad file:
message, no reboot) and idempotency.
"""

from __future__ import annotations

import re

import pytest

from app.domains.tr069 import script as S

ARGS = dict(
    acs_url="https://acs-staging.wyfyguest.com/",
    username="loc-11111111",
    password='Ab$c"d\\e',
    interval_s=300,
)

#: (router `version` output, architecture-name) -> URL that answered 200 with
#: an npk on 2026-10-24. x86/CHR ship without an arch suffix.
VERIFIED = {
    ("6.48.6 (long-term)", "mipsbe"): "6.48.6/tr069-client-6.48.6-mipsbe.npk",
    ("6.48.6 (long-term)", "x86"): "6.48.6/tr069-client-6.48.6.npk",
    ("6.49.17 (long-term)", "arm"): "6.49.17/tr069-client-6.49.17-arm.npk",
    ("6.49.17 (long-term)", "smips"): "6.49.17/tr069-client-6.49.17-smips.npk",
    ("6.49.17 (long-term)", "tile"): "6.49.17/tr069-client-6.49.17-tile.npk",
    ("6.49.17 (long-term)", "ppc"): "6.49.17/tr069-client-6.49.17-ppc.npk",
    ("7.1 (stable)", "arm64"): "7.1/tr069-client-7.1-arm64.npk",
    ("7.1 (stable)", "mmips"): "7.1/tr069-client-7.1-mmips.npk",
    ("7.12 (stable)", "arm"): "7.12/tr069-client-7.12-arm.npk",
    ("7.12 (stable)", "x86_64"): "7.12/tr069-client-7.12.npk",
    ("7.16.2 (stable)", "arm"): "7.16.2/tr069-client-7.16.2-arm.npk",
    ("7.16.2 (stable)", "mipsbe"): "7.16.2/tr069-client-7.16.2-mipsbe.npk",
    ("7.16.2 (stable)", "ppc"): "7.16.2/tr069-client-7.16.2-ppc.npk",
    ("7.23.8 (long-term)", "tile"): "7.23.8/tr069-client-7.23.8-tile.npk",
    ("7.25 (stable)", "arm64"): "7.25/tr069-client-7.25-arm64.npk",
    ("7.25 (stable)", "smips"): "7.25/tr069-client-7.25-smips.npk",
    ("7.25 (stable)", "x86"): "7.25/tr069-client-7.25.npk",
}
VERSIONS = ["6.48.6", "6.49.17", "6.49.23", "7.1", "7.12", "7.16.2", "7.23.8", "7.25"]


def _decode(literal: str) -> str:
    """RouterOS double-quoted string -> its text (\\" \\\\ \\$ \\n)."""
    assert literal.startswith('"') and literal.endswith('"')
    out, i, body = [], 0, literal[1:-1]
    while i < len(body):
        c = body[i]
        if c == "\\":
            nxt = body[i + 1]
            out.append("\n" if nxt == "n" else nxt)
            i += 2
            continue
        assert c != '"', "unescaped quote inside a literal"
        out.append(c)
        i += 1
    return "".join(out)


def _sources(text: str) -> dict[str, str]:
    found = {}
    for m in re.finditer(
        r'^/system script add name="([^"]+)" dont-require-permissions=yes source=(".*")$',
        text,
        re.M,
    ):
        found[m.group(1)] = _decode(m.group(2))
    return found


@pytest.fixture(scope="module")
def on() -> str:
    return S.render_tr069_script(**ARGS, enabled=True)


@pytest.fixture(scope="module")
def src(on) -> dict[str, str]:
    return _sources(on)


# -- the decision table -----------------------------------------------------


@pytest.mark.parametrize(("key", "url"), sorted(VERIFIED.items()))
def test_package_url_matches_the_verified_download(key, url) -> None:
    assert S.package_url(*key) == "https://download.mikrotik.com/routeros/" + url


@pytest.mark.parametrize("ver", VERSIONS)
@pytest.mark.parametrize("arch", sorted(S.ARCH_SUFFIX))
def test_every_version_and_architecture_has_a_url(ver, arch) -> None:
    url = S.package_url(f"{ver} (stable)", arch)
    suffix = "" if arch in ("x86", "x86_64") else f"-{arch}"
    assert (
        url
        == f"https://download.mikrotik.com/routeros/{ver}/tr069-client-{ver}{suffix}.npk"
    )


@pytest.mark.parametrize(
    ("raw", "ver"),
    [
        ("7.16.2 (stable)", "7.16.2"),
        ("7.23.8 (long-term)", "7.23.8"),
        ("7.26beta3 (testing)", "7.26beta3"),
        ("6.49.17 (long-term)", "6.49.17"),
        ("7.25", "7.25"),
    ],
)
def test_version_parse(raw, ver) -> None:
    assert S.router_version(raw) == ver


@pytest.mark.parametrize(
    ("raw", "arch"),
    [
        ("8.0 (stable)", "arm"),
        ("5.26", "mipsbe"),
        ("7.16.2 (stable)", "mipsle"),
        ("7.16.2 (stable)", "riscv"),
    ],
)
def test_unsupported_version_or_arch_has_no_url(raw, arch) -> None:
    assert S.package_url(raw, arch) is None


# -- the generated text -------------------------------------------------------


def test_three_scripts_are_installed_and_the_installer_runs(on, src) -> None:
    assert set(src) == {S.CONFIG_SCRIPT, S.AFTERBOOT_SCRIPT, S.INSTALL_SCRIPT}
    assert f"/system script run {S.INSTALL_SCRIPT}\n" in on


def test_console_lines_are_variable_free_single_statements(on) -> None:
    """The console runs each pasted line on its own; no line may read a
    variable or open a do-block outside a string (the setup panel's
    validator rules)."""
    for line in on.splitlines():
        if not line or line.startswith("#"):
            continue
        assert line.startswith("/system "), line
        bare = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
        assert "$" not in bare and "do={" not in bare, line


def test_every_add_is_preceded_by_a_remove_of_the_same_name(on, src) -> None:
    for name in src:
        rm = on.index(f'/system script remove [find where name="{name}"]')
        add = on.index(f'/system script add name="{name}"')
        assert rm < add
    install = src[S.INSTALL_SCRIPT]
    assert install.index(
        f'/system scheduler remove [find where name="{S.BOOT_SCHEDULER}"]'
    ) < install.index(f'/system scheduler add name="{S.BOOT_SCHEDULER}"')


def test_sources_are_balanced(src) -> None:
    for name, body in src.items():
        stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', body)
        assert stripped.count('"') % 2 == 0, name
        for o, c in ("{}", "[]", "()"):
            assert stripped.count(o) == stripped.count(c), (name, o)


def test_every_architecture_is_mapped_in_the_installer(src) -> None:
    install = src[S.INSTALL_SCRIPT]
    for arch, suffix in S.ARCH_SUFFIX.items():
        assert (
            f':if ($arch = "{arch}") do={{ :set suffix "{suffix}"; :set known true }}'
            in install
        )
    assert (
        ':local url ("https://download.mikrotik.com/routeros/" . $ver . "/" . $fn)'
        in install
    )
    assert ':local fn ("tr069-client-" . $ver . $suffix . ".npk")' in install
    assert ':if ([:typeof $sp] = "num") do={ :set ver [:pick $raw 0 $sp] }' in install


def test_skip_path_runs_config_and_never_reboots(src) -> None:
    install = src[S.INSTALL_SCRIPT]
    installed_branch = install[: install.index("} else={\n  :local ok true")]
    assert f"/system script run {S.CONFIG_SCRIPT}" in installed_branch
    assert "reboot" not in installed_branch.replace("WYFY", "")
    assert "/tool fetch url=$url" not in installed_branch


def test_reboot_is_the_last_step_and_only_after_every_check(src) -> None:
    install = src[S.INSTALL_SCRIPT]
    assert install.count("/system reboot") == 1
    reboot = install.index(':execute ":delay 10s; /system reboot"')
    for earlier in (
        "/tool fetch url=$url dst-path=$fn",
        "[/file get $f size]",
        f'/system scheduler add name="{S.BOOT_SCHEDULER}" start-time=startup',
        "router will reboot in 10s to install TR-069",
    ):
        assert install.index(earlier) < reboot, earlier
    # the reboot sits in the final `:if ($ok)` block, and nothing follows it
    final = install[install.rindex("  :if ($ok) do={\n") :]
    assert ':execute ":delay 10s; /system reboot"' in final
    assert install.rstrip().endswith('/system reboot"\n  }\n}')


@pytest.mark.parametrize(
    "marker",
    [
        "is not supported (6.x and 7.x only). Nothing changed, no reboot.",
        "is not supported. Nothing changed, no reboot.",
        "could not download/import the ISRG Root X1 certificate (check DNS and internet). Nothing changed, no reboot.",
        "(check DNS and internet). Nothing changed, no reboot.",
        "is not on the router after the download. No reboot.",
        "bytes); removed it. No reboot.",
    ],
)
def test_fail_paths_say_so_and_clear_ok(src, marker) -> None:
    install = src[S.INSTALL_SCRIPT]
    line = next(ln for ln in install.splitlines() if marker in ln)
    assert ":set ok false" in line


def test_fetch_failure_is_caught_not_fatal(src) -> None:
    install = src[S.INSTALL_SCRIPT]
    assert (
        ":do { /tool fetch url=$url dst-path=$fn } on-error={ :set ok false;" in install
    )


def test_afterboot_applies_config_then_removes_itself(src) -> None:
    boot = src[S.AFTERBOOT_SCRIPT]
    assert boot.startswith(":delay 20s")
    assert boot.index(f"/system script run {S.CONFIG_SCRIPT}") < boot.index(
        f'/system scheduler remove [find where name="{S.BOOT_SCHEDULER}"]'
    )
    assert boot.rstrip().endswith(
        f'/system script remove [find where name="{S.AFTERBOOT_SCRIPT}"]'
    )


def test_config_carries_the_credential_with_routeros_escaping(src) -> None:
    cfg = src[S.CONFIG_SCRIPT]
    assert 'acs-url="https://acs-staging.wyfyguest.com/"' in cfg
    assert 'username="loc-11111111"' in cfg
    assert 'password="Ab\\$c\\"d\\\\e"' in cfg
    assert (
        "periodic-inform-enabled=yes periodic-inform-interval=300s enabled=yes" in cfg
    )


def test_ca_import_only_when_missing_by_common_name(src) -> None:
    install = src[S.INSTALL_SCRIPT]
    guard = f':if ([:len [/certificate find where common-name="{S.CA_COMMON_NAME}"]] = 0) do={{'
    # two CA blocks (skip path and install path), each: guard + post-check
    assert install.count(guard) == 4
    # RouterOS 6 has no `name=` on import, so it is not used on either version
    assert (
        install.count(f'/certificate import file-name="{S.CA_FILE}" passphrase=""') == 2
    )
    assert "/certificate sign" not in install  # memory: the ca= self-sign trap


def test_disabled_location_never_downloads_or_reboots() -> None:
    off = S.render_tr069_script(**ARGS, enabled=False)
    srcs = _sources(off)
    assert "enabled=no" in srcs[S.CONFIG_SCRIPT]
    install = srcs[S.INSTALL_SCRIPT]
    assert "/system reboot" not in install and "/tool fetch" not in install
    assert "nothing to do" in install


def test_quoting_still_refuses_newlines_and_escapes() -> None:
    assert S.ros_quote('a"b\\c$d') == '"a\\"b\\\\c\\$d"'
    with pytest.raises(ValueError):
        S.ros_quote("a\nb")
    with pytest.raises(ValueError):
        S.render_tr069_script(**{**ARGS, "password": "a\nb"}, enabled=True)

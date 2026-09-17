"""Guards for deploy/remote-deploy.sh, the script that ships production.

Why this file exists: on 2026-09-17 a change here deleted the `compose_up()`
function definition while adding a new one above it. `bash -n` was clean --
a call to an undefined *function* is not a syntax error -- so every local
check passed, the deploy ran, and it died at line 323 with
`compose_up: command not found`. The script's own rollback did its job and
production stayed up on the previous image, but the deploy was burned and
the only signal was a production log.

Nothing else in this repository reads that script. It is not imported, not
linted, and `paths: backend/**` means a deploy-only change does not even
start CI of its own accord -- what saves it is that CD calls CI before it
deploys, so a test here is the one gate that runs before every production
deploy. That is why these assertions live in the backend suite rather than
next to the file they check.

The functional half runs the REAL `materialise_mail_env` -- extracted from
the script at test time, never copied -- against a fake `aws` on PATH. That
is the only way it caught its own first bug: `python3 -` reads the program
from stdin, so the JSON being piped in was consumed as code and `json.load`
saw an empty string, silently writing an empty mail.env.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY_SCRIPT = REPO_ROOT / "deploy" / "remote-deploy.sh"
COMPOSE_FILE = REPO_ROOT / "deploy" / "docker-compose.prod.yml"

#: Every helper the script calls by name. A definition missing from this list
#: is the 2026-09-17 failure: the call still parses, and fails on the box.
REQUIRED_HELPERS = (
    "log",
    "die",
    "current_image_of",
    "read_var",
    "set_var",
    "materialise_mail_env",
    "compose_up",
    "wait_healthy",
    "report",
)


def _script() -> str:
    return DEPLOY_SCRIPT.read_text(encoding="utf-8")


def test_every_helper_the_script_calls_is_defined() -> None:
    """The check that would have caught the deleted `compose_up`."""
    source = _script()
    missing = [
        name
        for name in REQUIRED_HELPERS
        # Both spelling styles in this file: `name()  {` and `name() {`.
        if f"\n{name}()" not in source
    ]
    assert not missing, (
        f"deploy/remote-deploy.sh calls these but no longer defines them: {missing}. "
        "`bash -n` cannot see this; the deploy fails on the box instead."
    )


def test_the_script_is_at_least_syntactically_valid() -> None:
    result = subprocess.run(
        ["bash", "-n", str(DEPLOY_SCRIPT)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_mail_env_is_loaded_after_the_base_env_file() -> None:
    """Order is the whole mechanism: later env_file entries win in compose, so
    mail.env must come second or the secret silently loses to the box's .env."""
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    base = "${BACKEND_ENV_FILE:-./cloud-guest/backend/.env}"
    mail = "${MAIL_ENV_FILE:-./mail.env}"
    for service in ("api", "celery-worker", "celery-beat"):
        block = _service_block(compose, service)
        assert base in block, f"{service} does not load the base env file"
        assert mail in block, f"{service} does not load the mail env file"
        assert block.index(base) < block.index(mail), (
            f"{service} loads mail.env BEFORE the base env file, so the base wins "
            "and the secret is ignored"
        )


def _service_block(compose: str, service: str) -> str:
    """One service's YAML, up to the next service. A plain `index("\\n  ")`
    is not good enough here: every nested line is indented further, so the
    first match is the line right after the service name."""
    start = compose.index(f"\n  {service}:")
    rest = compose[start + 1 :]
    nxt = re.search(r"\n  \S", rest)
    return rest[: nxt.start()] if nxt else rest


def test_the_mail_filter_is_called_for_the_backend_only() -> None:
    source = _script()
    assert 'if [[ "$SERVICE" == "api" ]]; then' in source
    assert "materialise_mail_env" in source
    # The frontend reads no mail keys, so its deploy must not touch the file.
    call = source[source.index('if [[ "$SERVICE" == "api" ]]') :]
    assert call.index("materialise_mail_env") < call.index("compose_up")


# ---------------------------------------------------------------------------
# The real function, run against a fake aws
# ---------------------------------------------------------------------------

FULL_SECRET = """{
  "CLOUDGUEST_SMTP_HOST": "smtp.gmail.com",
  "CLOUDGUEST_SMTP_PORT": "587",
  "CLOUDGUEST_SMTP_USERNAME": "sales@wyfyguest.com",
  "CLOUDGUEST_SMTP_PASSWORD": "sales-app-password",
  "CLOUDGUEST_SMTP_USE_TLS": "true",
  "CLOUDGUEST_SMTP_FROM_ADDRESS": "sales@wyfyguest.com",
  "CLOUDGUEST_DEMO_SMTP_HOST": "smtp.gmail.com",
  "CLOUDGUEST_DEMO_SMTP_PORT": "587",
  "CLOUDGUEST_DEMO_SMTP_USERNAME": "demo@wyfyguest.com",
  "CLOUDGUEST_DEMO_SMTP_PASSWORD": "",
  "CLOUDGUEST_DEMO_SMTP_USE_TLS": "true",
  "CLOUDGUEST_DEMO_SMTP_FROM_ADDRESS": "demo@wyfyguest.com",
  "CLOUDGUEST_DEMO_REQUEST_NOTIFY_EMAIL": "demo@wyfyguest.com"
}"""


def _run_materialise(tmp_path: Path, aws_output: str, aws_exit: int = 0) -> str:
    """Extract `materialise_mail_env` from the script and run it for real."""
    source = _script()
    start = source.index("materialise_mail_env() {")
    end = source.index("\n}\n", start) + len("\n}\n")
    (tmp_path / "fn.sh").write_text(source[start:end], encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_aws = fake_bin / "aws"
    fake_aws.write_text(
        "#!/bin/bash\nprintf '%s' " + _sh_quote(aws_output) + f"\nexit {aws_exit}\n",
        encoding="utf-8",
    )
    fake_aws.chmod(0o755)

    target = tmp_path / "mail.env"
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "set -uo pipefail\n"
        'log() { echo "[test] $*"; }\n'
        "REGION=ap-south-1\n"
        "MAIL_SECRET_ID=cloudguest/prod/mail\n"
        f"MAIL_ENV_FILE={target}\n"
        f'source "{tmp_path / "fn.sh"}"\n'
        "materialise_mail_env\n",
        encoding="utf-8",
    )
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
    result = subprocess.run(
        ["bash", str(harness)], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    return target.read_text(encoding="utf-8") if target.exists() else ""


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def test_only_mailboxes_with_a_password_are_written(tmp_path: Path) -> None:
    """The whole point of the gate: a mailbox whose password is still blank
    must be left exactly as the box has it, or the app is handed a host with
    nothing to authenticate it and every send 535s."""
    written = _run_materialise(tmp_path, FULL_SECRET)

    lines = sorted(line for line in written.splitlines() if line)
    assert "CLOUDGUEST_SMTP_PASSWORD=sales-app-password" in lines
    assert "CLOUDGUEST_DEMO_REQUEST_NOTIFY_EMAIL=demo@wyfyguest.com" in lines
    # sales@'s six keys, plus the notify address. Nothing from demo@.
    assert len(lines) == 7, lines
    assert not any(line.startswith("CLOUDGUEST_DEMO_SMTP_") for line in lines)


def test_a_filled_mailbox_is_written_whole(tmp_path: Path) -> None:
    filled = FULL_SECRET.replace(
        '"CLOUDGUEST_DEMO_SMTP_PASSWORD": ""',
        '"CLOUDGUEST_DEMO_SMTP_PASSWORD": "demo-pw"',
    )
    written = _run_materialise(tmp_path, filled)

    lines = sorted(line for line in written.splitlines() if line)
    assert "CLOUDGUEST_DEMO_SMTP_PASSWORD=demo-pw" in lines
    assert "CLOUDGUEST_DEMO_SMTP_HOST=smtp.gmail.com" in lines
    assert "CLOUDGUEST_DEMO_SMTP_FROM_ADDRESS=demo@wyfyguest.com" in lines
    assert len(lines) == 13, lines  # both mailboxes, six keys each, plus notify


def test_a_denied_secret_writes_nothing_and_does_not_fail_the_deploy(
    tmp_path: Path,
) -> None:
    """Fail open: mail configuration is not what a deploy is for."""
    written = _run_materialise(
        tmp_path, "An error occurred (AccessDeniedException)", aws_exit=254
    )
    assert written == ""


def test_a_secret_that_is_not_json_writes_nothing(tmp_path: Path) -> None:
    assert _run_materialise(tmp_path, "not json at all") == ""


def test_values_are_never_printed(tmp_path: Path) -> None:
    """What the box's log is allowed to contain. A password in a deploy log is
    a password in every log aggregator that reads it.

    The failure path deliberately DOES log the `aws` error text -- that is an
    error message, not a secret, and without it a denied GetSecretValue is
    undebuggable. What must never happen is a *parsed value* reaching stdout:
    the summary is the count and the mailbox NAMES, and the only other output
    is the file itself.
    """
    source = _script()
    start = source.index("materialise_mail_env() {")
    body = source[start : source.index("\n}\n", start)]

    assert 'log "mail.env: ${summary' in body
    for line in body.splitlines():
        if line.strip().startswith("log "):
            assert "PASSWORD" not in line, line

    # The embedded python prints exactly one thing, and it is a summary.
    prints = [line.strip() for line in body.splitlines() if "print(" in line]
    assert prints, "the filter should report what it did"
    for line in prints:
        assert (
            "out[" not in line and "value" not in line
        ), f"the filter prints something derived from a value: {line}"

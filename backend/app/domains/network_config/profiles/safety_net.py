"""Scheduled-revert safety net profile (Wave 1 Step 11)."""

from __future__ import annotations

from app.domains.provisioning_engine.planner.constants import (
    PROVISIONING_ENGINE_BACKUP_NAME,
    SAFETY_REVERT_INTERVAL,
    SAFETY_REVERT_SCHEDULER_COMMENT,
)

from .constants import wyfy_comment


def _escape_routeros_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_safety_revert_scheduler(
    *,
    backup_name: str = PROVISIONING_ENGINE_BACKUP_NAME,
) -> list[str]:
    """Install a self-revert scheduler before risky plan steps run."""
    comment = SAFETY_REVERT_SCHEDULER_COMMENT
    backup = _escape_routeros_string(backup_name)
    interval = _escape_routeros_string(SAFETY_REVERT_INTERVAL)
    on_event = (
        f'/system backup load name="{backup}"; /system reboot;'
    )
    return [
        "# --- WyFyGuest management safety net (scheduled revert) ---",
        (
            f':local wyfySafetySched [/system scheduler find where '
            f'comment="{comment}"]'
        ),
        (
            ":if ([:len $wyfySafetySched] > 0) do={ "
            "/system scheduler remove $wyfySafetySched }"
        ),
        (
            f':if ([:len [/system scheduler find where comment="{comment}"]] = 0) do={{'
        ),
        (
            f'  /system scheduler add name="wyfy-safety-revert" interval={interval} '
            f'start-time=startup on-event="{on_event}" comment="{comment}"'
        ),
        "}",
    ]


def render_safety_revert_cleanup() -> list[str]:
    comment = SAFETY_REVERT_SCHEDULER_COMMENT
    return [
        "# --- WyFyGuest remove safety revert scheduler ---",
        (
            f':local wyfySafetySched [/system scheduler find where '
            f'comment="{comment}"]'
        ),
        (
            ":if ([:len $wyfySafetySched] > 0) do={ "
            "/system scheduler remove $wyfySafetySched }"
        ),
    ]


def render_pre_apply_export_marker(*, snapshot_id: str) -> str:
    tag = wyfy_comment("pre-apply", "export")
    return (
        f"# {tag} snapshot={snapshot_id}\n"
        "# Pre-apply /export capture is performed at push time (Step 12)."
    )


__all__ = [
    "render_safety_revert_scheduler",
    "render_safety_revert_cleanup",
    "render_pre_apply_export_marker",
]

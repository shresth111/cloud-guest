"""Deterministic compatibility evaluator for a router discovery snapshot.

No device I/O. Operates on already-collected snapshot fields (ORM row or
plain dicts) and returns ``overall`` + per-check results.

Rules (Wave 1 — keep simple and unit-testable):

1. **RouterOS version** — parse major from ``routeros_version``.
   Major ``>= 7`` → PASS; major ``< 7`` or unparseable → BLOCKED.
2. **Model** — known-unsupported set is empty for Wave 1 → always PASS
   when model is present; missing model → soft WARNING.
3. **Free memory** — ``free_memory_bytes``:
   ``< 8 MiB`` → BLOCKED; ``< 16 MiB`` → WARNING; missing → WARNING;
   otherwise PASS.
4. **Free storage** — ``free_storage_bytes``:
   ``< 2 MiB`` → BLOCKED; ``< 5 MiB`` → WARNING; missing → WARNING;
   otherwise PASS.
5. **Hotspot package** — informational: if ``hotspot_state.server_count > 0``
   or packages list mentions hotspot → PASS; if packages list is empty
   (unknown) → WARNING; otherwise PASS noting hotspot package not listed
   (guest Wi-Fi may still work via system package on RouterOS 7).

Overall roll-up: worst status wins
(``BLOCKED > ERROR > WARNING > PASS``).
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from .constants import CompatibilityCheckStatus, CompatibilityOverall
from .schemas import CompatibilityCheck, CompatibilityReport

_MIB = 1024 * 1024
_FREE_MEMORY_BLOCKED = 8 * _MIB
_FREE_MEMORY_WARNING = 16 * _MIB
_FREE_STORAGE_BLOCKED = 2 * _MIB
_FREE_STORAGE_WARNING = 5 * _MIB

# Wave 1: empty — soft-warn only when model is missing.
UNSUPPORTED_MODELS: frozenset[str] = frozenset()

_STATUS_RANK: dict[CompatibilityCheckStatus, int] = {
    CompatibilityCheckStatus.PASS: 0,
    CompatibilityCheckStatus.WARNING: 1,
    CompatibilityCheckStatus.ERROR: 2,
    CompatibilityCheckStatus.BLOCKED: 3,
}

_VERSION_MAJOR_RE = re.compile(r"^(\d+)")


class SnapshotLike(Protocol):
    """Minimal surface the evaluator needs from an ORM row or stand-in."""

    routeros_version: str | None
    model: str | None
    free_memory_bytes: int | None
    free_storage_bytes: int | None
    packages: list[Any] | None
    hotspot_state: dict[str, Any] | None


def parse_routeros_major(version: str | None) -> int | None:
    """Extract the leading major version integer, or ``None`` if absent/bad."""
    if not version:
        return None
    # RouterOS often reports "7.15.3 (stable)" — take the leading digits.
    match = _VERSION_MAJOR_RE.match(version.strip())
    if not match:
        return None
    return int(match.group(1))


def _check_routeros_version(version: str | None) -> CompatibilityCheck:
    major = parse_routeros_major(version)
    if major is None:
        return CompatibilityCheck(
            name="routeros_version",
            status=CompatibilityCheckStatus.BLOCKED,
            detail="RouterOS version missing or unparseable; RouterOS 7+ required",
        )
    if major < 7:
        return CompatibilityCheck(
            name="routeros_version",
            status=CompatibilityCheckStatus.BLOCKED,
            detail=f"RouterOS {version} is below major 7 (required)",
        )
    return CompatibilityCheck(
        name="routeros_version",
        status=CompatibilityCheckStatus.PASS,
        detail=f"RouterOS {version} (major {major}) meets the RouterOS 7+ requirement",
    )


def _check_model(model: str | None) -> CompatibilityCheck:
    if not model:
        return CompatibilityCheck(
            name="model",
            status=CompatibilityCheckStatus.WARNING,
            detail="Router model was not reported by the device",
        )
    if model in UNSUPPORTED_MODELS:
        return CompatibilityCheck(
            name="model",
            status=CompatibilityCheckStatus.BLOCKED,
            detail=f"Model {model} is on the unsupported list",
        )
    return CompatibilityCheck(
        name="model",
        status=CompatibilityCheckStatus.PASS,
        detail=f"Model {model} is accepted",
    )


def _check_free_memory(free_memory_bytes: int | None) -> CompatibilityCheck:
    if free_memory_bytes is None:
        return CompatibilityCheck(
            name="free_memory",
            status=CompatibilityCheckStatus.WARNING,
            detail="Free memory was not reported by the device",
        )
    if free_memory_bytes < _FREE_MEMORY_BLOCKED:
        return CompatibilityCheck(
            name="free_memory",
            status=CompatibilityCheckStatus.BLOCKED,
            detail=(
                f"Free memory {free_memory_bytes} bytes is below "
                f"{_FREE_MEMORY_BLOCKED} (8 MiB)"
            ),
        )
    if free_memory_bytes < _FREE_MEMORY_WARNING:
        return CompatibilityCheck(
            name="free_memory",
            status=CompatibilityCheckStatus.WARNING,
            detail=(
                f"Free memory {free_memory_bytes} bytes is below "
                f"{_FREE_MEMORY_WARNING} (16 MiB)"
            ),
        )
    return CompatibilityCheck(
        name="free_memory",
        status=CompatibilityCheckStatus.PASS,
        detail=f"Free memory {free_memory_bytes} bytes is sufficient",
    )


def _check_free_storage(free_storage_bytes: int | None) -> CompatibilityCheck:
    if free_storage_bytes is None:
        return CompatibilityCheck(
            name="free_storage",
            status=CompatibilityCheckStatus.WARNING,
            detail="Free storage was not reported by the device",
        )
    if free_storage_bytes < _FREE_STORAGE_BLOCKED:
        return CompatibilityCheck(
            name="free_storage",
            status=CompatibilityCheckStatus.BLOCKED,
            detail=(
                f"Free storage {free_storage_bytes} bytes is below "
                f"{_FREE_STORAGE_BLOCKED} (2 MiB)"
            ),
        )
    if free_storage_bytes < _FREE_STORAGE_WARNING:
        return CompatibilityCheck(
            name="free_storage",
            status=CompatibilityCheckStatus.WARNING,
            detail=(
                f"Free storage {free_storage_bytes} bytes is below "
                f"{_FREE_STORAGE_WARNING} (5 MiB)"
            ),
        )
    return CompatibilityCheck(
        name="free_storage",
        status=CompatibilityCheckStatus.PASS,
        detail=f"Free storage {free_storage_bytes} bytes is sufficient",
    )


def _package_names(packages: list[Any] | None) -> list[str]:
    names: list[str] = []
    for item in packages or []:
        if isinstance(item, dict):
            name = item.get("name")
            if name:
                names.append(str(name).lower())
        elif isinstance(item, str):
            names.append(item.lower())
    return names


def _check_hotspot_package(
    packages: list[Any] | None,
    hotspot_state: dict[str, Any] | None,
) -> CompatibilityCheck:
    state = hotspot_state or {}
    server_count = int(state.get("server_count") or 0)
    names = _package_names(packages)
    has_hotspot_pkg = any("hotspot" in name for name in names)

    if server_count > 0 or has_hotspot_pkg:
        detail = (
            f"Hotspot present (servers={server_count}, "
            f"package_listed={has_hotspot_pkg})"
        )
        return CompatibilityCheck(
            name="hotspot_package",
            status=CompatibilityCheckStatus.PASS,
            detail=detail,
        )
    if not names:
        return CompatibilityCheck(
            name="hotspot_package",
            status=CompatibilityCheckStatus.WARNING,
            detail="Package list empty; cannot confirm hotspot package availability",
        )
    return CompatibilityCheck(
        name="hotspot_package",
        status=CompatibilityCheckStatus.PASS,
        detail=(
            "No hotspot servers or hotspot package listed; "
            "informational only on RouterOS 7"
        ),
    )


def _roll_up(checks: list[CompatibilityCheck]) -> CompatibilityOverall:
    worst = CompatibilityCheckStatus.PASS
    for check in checks:
        if _STATUS_RANK[check.status] > _STATUS_RANK[worst]:
            worst = check.status
    return CompatibilityOverall(worst.value)


def evaluate_compatibility(snapshot: SnapshotLike) -> CompatibilityReport:
    """Run all Wave 1 compatibility checks against ``snapshot``."""
    checks = [
        _check_routeros_version(snapshot.routeros_version),
        _check_model(snapshot.model),
        _check_free_memory(snapshot.free_memory_bytes),
        _check_free_storage(snapshot.free_storage_bytes),
        _check_hotspot_package(snapshot.packages, snapshot.hotspot_state),
    ]
    return CompatibilityReport(overall=_roll_up(checks), checks=checks)


def evaluate_compatibility_from_fields(
    *,
    routeros_version: str | None = None,
    model: str | None = None,
    free_memory_bytes: int | None = None,
    free_storage_bytes: int | None = None,
    packages: list[Any] | None = None,
    hotspot_state: dict[str, Any] | None = None,
) -> CompatibilityReport:
    """Convenience wrapper for unit tests / dict-shaped inputs."""

    class _Fields:
        pass

    fields = _Fields()
    fields.routeros_version = routeros_version  # type: ignore[attr-defined]
    fields.model = model  # type: ignore[attr-defined]
    fields.free_memory_bytes = free_memory_bytes  # type: ignore[attr-defined]
    fields.free_storage_bytes = free_storage_bytes  # type: ignore[attr-defined]
    fields.packages = packages  # type: ignore[attr-defined]
    fields.hotspot_state = hotspot_state  # type: ignore[attr-defined]
    return evaluate_compatibility(fields)  # type: ignore[arg-type]


__all__ = [
    "UNSUPPORTED_MODELS",
    "SnapshotLike",
    "parse_routeros_major",
    "evaluate_compatibility",
    "evaluate_compatibility_from_fields",
]

"""Final router verification evaluator (P19 / Wave 1 Step 12)."""

from __future__ import annotations

from .constants import FinalVerificationOverall, VerificationCheckStatus
from .schemas import VerificationCheck


def _check(
    *,
    name: str,
    status: VerificationCheckStatus,
    observed: str | None = None,
    expected: str | None = None,
    detail: str | None = None,
) -> VerificationCheck:
    return VerificationCheck(
        name=name,
        status=status,
        observed=observed,
        expected=expected,
        detail=detail,
        duration_ms=0,
    )


def evaluate_final_verification(
    *,
    apply_succeeded: bool,
    router_online: bool,
    wan_gate_passes: bool,
    api_reachable: bool,
    wireguard_healthy: bool | None,
) -> tuple[FinalVerificationOverall, list[VerificationCheck]]:
    checks: list[VerificationCheck] = []

    if apply_succeeded:
        checks.append(
            _check(
                name="plan_apply",
                status=VerificationCheckStatus.PASS,
                observed="applied",
                expected="applied",
            )
        )
    else:
        checks.append(
            _check(
                name="plan_apply",
                status=VerificationCheckStatus.ERROR,
                observed="not_applied",
                expected="applied",
            )
        )
        return FinalVerificationOverall.FAILED, checks

    checks.append(
        _check(
            name="router_online",
            status=VerificationCheckStatus.PASS
            if router_online
            else VerificationCheckStatus.ERROR,
            observed="online" if router_online else "offline",
            expected="online",
        )
    )
    checks.append(
        _check(
            name="wan_gate",
            status=VerificationCheckStatus.PASS
            if wan_gate_passes
            else VerificationCheckStatus.ERROR,
            observed="pass" if wan_gate_passes else "fail",
            expected="pass",
        )
    )
    checks.append(
        _check(
            name="api_reachability",
            status=VerificationCheckStatus.PASS
            if api_reachable
            else VerificationCheckStatus.ERROR,
            observed="healthy" if api_reachable else "unhealthy",
            expected="healthy",
        )
    )

    if wireguard_healthy is None:
        checks.append(
            _check(
                name="wireguard",
                status=VerificationCheckStatus.WARNING,
                observed="not_configured",
                detail="No WireGuard tunnel configured",
            )
        )
    else:
        checks.append(
            _check(
                name="wireguard",
                status=VerificationCheckStatus.PASS
                if wireguard_healthy
                else VerificationCheckStatus.ERROR,
                observed="healthy" if wireguard_healthy else "unhealthy",
                expected="healthy",
            )
        )

    hard_fail = not router_online or not wan_gate_passes or not api_reachable
    if hard_fail:
        return FinalVerificationOverall.FAILED, checks

    if wireguard_healthy is False:
        return FinalVerificationOverall.PARTIAL, checks

    return FinalVerificationOverall.ROUTER_ONLINE, checks


__all__ = ["evaluate_final_verification"]

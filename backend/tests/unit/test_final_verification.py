"""Unit tests for Wave 1 Step 12 final verification and plan apply helpers."""

from __future__ import annotations

from app.domains.provisioning_engine.planner.constants import FinalVerificationOverall
from app.domains.provisioning_engine.planner.final_verification import (
    evaluate_final_verification,
)


def test_final_verification_router_online() -> None:
    overall, checks = evaluate_final_verification(
        apply_succeeded=True,
        router_online=True,
        wan_gate_passes=True,
        api_reachable=True,
        wireguard_healthy=True,
    )
    assert overall is FinalVerificationOverall.ROUTER_ONLINE
    assert len(checks) == 5


def test_final_verification_partial_when_wireguard_unhealthy() -> None:
    overall, _checks = evaluate_final_verification(
        apply_succeeded=True,
        router_online=True,
        wan_gate_passes=True,
        api_reachable=True,
        wireguard_healthy=False,
    )
    assert overall is FinalVerificationOverall.PARTIAL


def test_final_verification_failed_when_apply_not_succeeded() -> None:
    overall, checks = evaluate_final_verification(
        apply_succeeded=False,
        router_online=True,
        wan_gate_passes=True,
        api_reachable=True,
        wireguard_healthy=True,
    )
    assert overall is FinalVerificationOverall.FAILED
    assert checks[0].name == "plan_apply"


def test_final_verification_failed_when_offline() -> None:
    overall, _checks = evaluate_final_verification(
        apply_succeeded=True,
        router_online=False,
        wan_gate_passes=True,
        api_reachable=True,
        wireguard_healthy=None,
    )
    assert overall is FinalVerificationOverall.FAILED

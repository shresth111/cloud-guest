"""Domain exceptions for router discovery / snapshot / compatibility."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "PlannerError",
    "RouterSnapshotNotFoundError",
    "NoRouterSnapshotError",
    "DiscoveryMissingCredentialsError",
    "DiscoveryDeviceConnectionError",
    "DiscoveryPreconditionsUnmetError",
    "NoWanLinksToVerifyError",
    "ConfigurationPlanNotFoundError",
    "ConfigurationPlanNotApprovableError",
    "ConfigurationPlanNotRenderableError",
    "ConfigurationPlanNotPreparableError",
    "ConfigurationPlanNotAppliableError",
    "ConfigurationPlanNotVerifiableError",
]


class PlannerError(CloudGuestError):
    """Base exception for the discovery / planner package."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class RouterSnapshotNotFoundError(PlannerError):
    def __init__(self, snapshot_id: uuid.UUID) -> None:
        super().__init__(
            f"Router snapshot '{snapshot_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class NoRouterSnapshotError(PlannerError):
    """Raised when compatibility is requested but the router has no snapshots."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"No discovery snapshot exists for router '{router_id}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DiscoveryMissingCredentialsError(PlannerError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class DiscoveryPreconditionsUnmetError(PlannerError):
    """Discovery refused *before* opening a socket, naming what is missing.

    A 400, not a 502: nothing was attempted against the device, so this
    is a statement about the platform's own records, not about the
    device's reachability. Reporting it as a gateway error would tell an
    operator to go look at a router that was never dialled.

    ``data["preconditions"]`` carries every check, not only the failing
    ones. The unmet ones say what to fix; the ``unknown`` ones say what
    could not be established at all, and dropping those would let a
    caller render "one thing is wrong" over a report that actually means
    "one thing is wrong and two others are unknowable from here".
    """

    def __init__(self, report: object) -> None:
        self.report = report
        checks = getattr(report, "checks", ())
        summary = getattr(report, "summary", None)
        super().__init__(
            str(summary or "Discovery preconditions are unmet"),
            status_code=status.HTTP_400_BAD_REQUEST,
            data={
                "preconditions": [
                    {
                        "key": str(check.key),
                        "label": check.label,
                        "status": str(check.status),
                        "detail": check.detail,
                        "next_step": check.next_step,
                    }
                    for check in checks
                ]
            },
        )


class DiscoveryDeviceConnectionError(PlannerError):
    """The device was genuinely dialled and did not answer.

    ``candidates`` is what turns this from honest into *identifying*. The
    transport's own words are always preserved verbatim -- masking them
    would be its own bug -- but a bare "timed out" names none of the
    several independent things that could produce it, and each has a
    different fix. When the caller has already established that every
    checkable precondition passed, it passes the remaining suspects here
    so the message ends by saying what is actually left to look at.
    """

    def __init__(
        self, host: str, detail: str, *, candidates: list[str] | None = None
    ) -> None:
        self.host = host
        self.detail = detail
        self.candidates = candidates or []
        message = f"Could not connect to device at '{host}' for discovery: {detail}"
        if self.candidates:
            message += (
                ". Every precondition the platform can check from here passed, "
                "so what remains is one of: "
                + "; ".join(self.candidates)
                + "."
            )
        super().__init__(message, status_code=status.HTTP_502_BAD_GATEWAY)


class NoWanLinksToVerifyError(PlannerError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' has no enabled WAN links to verify",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationPlanNotFoundError(PlannerError):
    def __init__(self, plan_id: uuid.UUID) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConfigurationPlanNotApprovableError(PlannerError):
    def __init__(self, plan_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' cannot be approved from status "
            f"'{current_status}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationPlanNotRenderableError(PlannerError):
    def __init__(self, plan_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' cannot be rendered from status "
            f"'{current_status}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationPlanNotPreparableError(PlannerError):
    def __init__(self, plan_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' cannot be prepared from status "
            f"'{current_status}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationPlanNotAppliableError(PlannerError):
    def __init__(self, plan_id: uuid.UUID, detail: str) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' cannot be applied: {detail}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConfigurationPlanNotVerifiableError(PlannerError):
    def __init__(self, plan_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Configuration plan '{plan_id}' cannot be final-verified from status "
            f"'{current_status}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

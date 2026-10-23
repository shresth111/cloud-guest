"""Entitlement and licence gates for ISP twins (ADDENDUM_04 §1).

WHY THIS EXISTS
---------------
A twin calls the ORIGINAL customer handler as a plain function, so every
route-level and router-level dependency of the original route is skipped. Two
of those dependencies are business gates rather than access checks:

- ``RequireFeature(<key>)`` -- the plan/add-on gate (402 ``feature_not_entitled``);
- ``RequireActiveLicenseForWrites()`` -- the ``_PAID_WRITES`` list applied at
  ``include_router`` in ``app.api.v1.router`` (402 ``license_not_active`` on a
  state-changing request when the licence has lapsed).

Both of them read the organization from ``X-Organization-Id``, which on an
``/isp`` request is the ISP's own org. Re-running them as-is would therefore
check the wrong organization. This module evaluates the SAME checks, through
the SAME billing helpers and errors, against the CUSTOMER org the twin
resolved through ``IspScope``.

Nothing here edits billing code: it imports ``_require_active_license`` (the
shared body of ``RequireActiveLicense``/``RequireActiveLicenseForWrites``) and
``EntitlementChecker.get_snapshot(...).has_feature(...)`` exactly as
``RequireFeature`` uses them.

``tests/unit/test_isp_partner_twin_gates.py`` walks every twin and compares
the gates it declares here against the dependencies of its original route, so
a ``RequireFeature`` added upstream later turns that test red.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import (
    _SAFE_HTTP_METHODS,
    _require_active_license,
    get_entitlement_checker,
)
from app.domains.billing.exceptions import FeatureNotEntitledError

__all__ = [
    "GATE_KWARG",
    "HAND_TWIN_GATES",
    "HandTwinGate",
    "enforce_customer_gates",
    "get_twin_entitlement_checker",
    "is_write",
]

#: The keyword under which ``build_twin`` receives the entitlement checker.
#: Underscored so it can never collide with a handler or request parameter.
GATE_KWARG = "_twin_entitlements"

#: The provider twins use. Re-exported so tests can override one name.
get_twin_entitlement_checker = get_entitlement_checker


def is_write(method: str) -> bool:
    """The same "state-changing" definition ``RequireActiveLicenseForWrites`` uses."""
    return method.upper() not in _SAFE_HTTP_METHODS


async def enforce_customer_gates(
    checker,
    organization_id: uuid.UUID | None,
    *,
    method: str,
    paid_write: bool,
    features: Iterable[PlanFeatureKey] = (),
) -> None:
    """Raise the original 402 if the CUSTOMER org fails a gate.

    - ``features``: ``RequireFeature`` semantics -- the licence must be active
      (for reads too, because ``RequireFeature`` implies ``RequireActiveLicense``)
      and the plan/overrides must enable every key.
    - ``paid_write``: ``RequireActiveLicenseForWrites`` semantics -- only on a
      state-changing method.

    Fails closed: a gated twin with no organization or no checker is refused,
    rather than silently skipping the gate the way a ``None`` organization
    context does on the customer side (that convention is for GLOBAL platform
    callers, which an ISP never is).
    """
    features = tuple(features)
    if PlanFeatureKey.WHITE_LABEL in features:
        from .policy import get_isp_partner_policy

        if get_isp_partner_policy().white_label == "off" and organization_id:
            # F4 flip: no white-label twin for ISPs at all.
            raise FeatureNotEntitledError(
                organization_id, PlanFeatureKey.WHITE_LABEL.value
            )
    needs_licence = bool(features) or (paid_write and is_write(method))
    if not needs_licence:
        return
    if organization_id is None or checker is None:
        raise RuntimeError(
            "a gated ISP twin reached its gate without a customer org or an "
            "entitlement checker"
        )
    await _require_active_license(organization_id, checker)
    if features:
        snapshot = await checker.get_snapshot(organization_id)
        for key in features:
            if not snapshot.has_feature(key):
                raise FeatureNotEntitledError(organization_id, key.value)


class HandTwinGate:
    """What a hand-written twin in ``router.py`` declares about its original."""

    __slots__ = ("features", "original", "paid_write")

    def __init__(
        self,
        original: str,
        *,
        paid_write: bool,
        features: tuple[PlanFeatureKey, ...] = (),
    ) -> None:
        #: ``"<module>:<function>"`` of the original customer handler.
        self.original = original
        self.paid_write = paid_write
        self.features = features


#: Every hand-written twin in ``router.py`` (§4.6 setup, §4.7 portal), keyed by
#: its endpoint function name. The parity test asserts this inventory is
#: complete (an AST scan of ``router.py`` for calls into another domain's
#: router module) and that each entry matches its original route's gates.
HAND_TWIN_GATES: dict[str, HandTwinGate] = {
    # §4.6 router setup. The router / wireguard / RADIUS-NAS families are
    # deliberately NOT on _PAID_WRITES (app.api.v1.router), so no gate.
    "twin_provisioning_token": HandTwinGate(
        "app.domains.router.router:generate_provisioning_token", paid_write=False
    ),
    "twin_regenerate_agent_credential": HandTwinGate(
        "app.domains.router.router:regenerate_agent_credential", paid_write=False
    ),
    "twin_allocate_tunnel": HandTwinGate(
        "app.domains.wireguard.router:allocate_external_wireguard_peer",
        paid_write=False,
    ),
    "twin_register_nas": HandTwinGate(
        "app.domains.guest.router:register_external_radius_nas", paid_write=False
    ),
    # §4.7 captive portal: the captive_portal router IS on _PAID_WRITES.
    "list_portal_configs": HandTwinGate(
        "app.domains.captive_portal.router:list_captive_portal_configs",
        paid_write=False,  # a GET; reads are never licence-gated
    ),
    "get_portal_config": HandTwinGate(
        "app.domains.captive_portal.router:get_captive_portal_config",
        paid_write=False,
    ),
    "update_portal_config": HandTwinGate(
        "app.domains.captive_portal.router:update_captive_portal_config",
        paid_write=True,
    ),
    "activate_portal_config": HandTwinGate(
        "app.domains.captive_portal.router:activate_captive_portal_config",
        paid_write=True,
    ),
    "upload_portal_content_image": HandTwinGate(
        "app.domains.captive_portal.router:upload_captive_portal_content_image",
        paid_write=True,
    ),
}

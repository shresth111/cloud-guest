"""The rest of the vendor-gating audit -- network_integration contract 11.5.

11.5 named fifteen domains to audit for surfaces that assume every fleet row
is a MikroTik running this platform's agent. Ten were closed when the Omada
integration landed: seven dispatch through per-vendor adapter registries and
refuse ``tplink_omada`` explicitly (``network_diagnostics``,
``provisioning_engine``, ``qos``, ``queue_management``, ``dhcp``, ``vlan``,
``port_forwarding``), and three were gated directly (``readiness``,
``monitoring``'s ZTP dashboard, and provisioning-token minting).

This file closes the remaining six: ``router_agent``, ``device_sync``,
``hotspot``, ``network_config``, ``firewall`` and ``wireguard``.

## What the audit found

Two of the six could actually do something wrong; four could not.

**``wireguard`` was a real defect, and the worst kind: irreversible.**
``validate_router_eligible_for_wireguard`` checked only ``Router.status``,
and a synthetic controller row is ``pending_provisioning`` -- an eligible
status. So a controller could be allocated a hub tunnel. The hub agent
exposes ``POST /wg/peer`` and ``GET /wg/peers`` and *no delete verb*, and
``next_free_ip()`` scans live kernel state, so that allocation permanently
consumes a peer and an address from the hub's /24 -- for a device that will
never run WireGuard. Nothing downstream would ever have reported it, because
a peer that never handshakes is indistinguishable from a device someone has
not finished configuring.

**``network_config`` failed closed but said the wrong thing.** Its live-apply
endpoint refused on "Router has no stored connection details", which reads as
"add some and retry" for a device where no credential would ever help. It
also reached that refusal *after* ``reveal_credentials``, writing an audit
entry for a credential reveal that revealed nothing.

**``router_agent``, ``device_sync``, ``hotspot`` and ``firewall`` are
inventory/DB domains** with no device I/O at all -- their own module
docstrings say so and ``TestTheInventoryDomainsStayDeviceFree`` below checks
it rather than trusting them. A controller row in those tables is no more
broken than any other row: nothing there talks to a device, so nothing there
can lie about one.
"""

from __future__ import annotations

import ast
import pathlib
import uuid

import pytest

from app.domains.router.vendor_capabilities import is_controller_managed
from app.domains.wireguard.exceptions import (
    WireGuardRouterNotEligibleError,
    WireGuardVendorNotSupportedError,
)
from app.domains.wireguard.validators import validate_router_eligible_for_wireguard

_OMADA = "tplink_omada"


class _Row:
    """The three attributes these gates read off a fleet row."""

    def __init__(self, vendor: str = "mikrotik", status: str = "pending_provisioning"):
        self.id = uuid.uuid4()
        self.vendor = vendor
        self.status = status


# ============================================================================
# wireguard -- the real defect
# ============================================================================


class TestWireGuardRefusesAControllerATunnel:
    def test_a_controller_cannot_be_allocated_a_tunnel(self) -> None:
        with pytest.raises(WireGuardVendorNotSupportedError):
            validate_router_eligible_for_wireguard(_Row(vendor=_OMADA))

    def test_the_status_that_used_to_let_it_through(self) -> None:
        """`pending_provisioning` is the status every synthetic controller
        row carries, and it is not in the ineligible set -- which is exactly
        why the status check alone let a controller reach the hub."""
        row = _Row(vendor=_OMADA, status="pending_provisioning")
        with pytest.raises(WireGuardVendorNotSupportedError):
            validate_router_eligible_for_wireguard(row)

    def test_the_vendor_answer_is_given_before_the_status_answer(self) -> None:
        """A status is temporary -- reinstate the router and it becomes
        eligible. Reporting "wrong status" for a controller would send an
        operator looking for a state change that cannot help, so the
        permanent answer has to win even when both apply."""
        row = _Row(vendor=_OMADA, status="decommissioned")
        with pytest.raises(WireGuardVendorNotSupportedError):
            validate_router_eligible_for_wireguard(row)

    def test_the_refusal_says_why_and_names_the_vendor(self) -> None:
        try:
            validate_router_eligible_for_wireguard(_Row(vendor=_OMADA))
        except WireGuardVendorNotSupportedError as exc:
            assert _OMADA in str(exc)
            assert "controller" in str(exc).lower()
        else:  # pragma: no cover
            pytest.fail("expected a refusal")

    def test_it_is_422_not_409(self) -> None:
        """409 invites a retry. There is no later moment at which this
        one succeeds."""
        try:
            validate_router_eligible_for_wireguard(_Row(vendor=_OMADA))
        except WireGuardVendorNotSupportedError as exc:
            assert exc.status_code == 422
        else:  # pragma: no cover
            pytest.fail("expected a refusal")


class TestMikroTikIsUnaffected:
    """The gate has to be narrow: an existing customer's fleet behaves
    exactly as it did before this change."""

    def test_a_healthy_mikrotik_is_still_eligible(self) -> None:
        validate_router_eligible_for_wireguard(_Row(vendor="mikrotik"))

    def test_a_row_with_no_vendor_is_still_eligible(self) -> None:
        """Every row written before `vendor` was ever set."""

        class _Bare:
            id = uuid.uuid4()
            status = "online"

        validate_router_eligible_for_wireguard(_Bare())

    @pytest.mark.parametrize("bad", ["decommissioned", "suspended"])
    def test_the_status_rules_still_apply_to_mikrotik(self, bad: str) -> None:
        with pytest.raises(WireGuardRouterNotEligibleError):
            validate_router_eligible_for_wireguard(_Row(vendor="mikrotik", status=bad))


class TestTheGateRunsBeforeTheIrreversibleCall:
    """The allocation this refuses cannot be undone, so *where* the check
    sits in `allocate_tunnel_via_hub` is part of the fix, not an
    implementation detail. Checked structurally because a unit test that
    merely observes "the hub was not called" would still pass if the guard
    were moved after it and the test's fake happened to raise first.
    """

    def test_validate_precedes_every_hub_call_in_the_allocation_path(self) -> None:
        source = pathlib.Path("app/domains/wireguard/service.py").read_text()
        tree = ast.parse(source)
        fn = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef)
            and n.name == "allocate_tunnel_via_hub"
        )

        guard_line = None
        first_hub_line = None
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name == "validate_router_eligible_for_wireguard" and guard_line is None:
                guard_line = node.lineno
            # Anything that reaches the hub agent: allocating a peer, or
            # asking it what it currently holds.
            reaches_hub = name.startswith(
                ("allocate_peer", "hub_", "request_peer")
            ) or ("hub" in name and name != "allocate_tunnel_via_hub")
            if reaches_hub and (
                first_hub_line is None or node.lineno < first_hub_line
            ):
                first_hub_line = node.lineno

        assert guard_line is not None, (
            "allocate_tunnel_via_hub no longer calls "
            "validate_router_eligible_for_wireguard -- the vendor gate is gone"
        )
        if first_hub_line is not None:
            assert guard_line < first_hub_line, (
                "the eligibility guard now runs AFTER a hub call; the hub has "
                "no delete verb, so anything it mints past this point leaks"
            )


# ============================================================================
# network_config -- failed closed, but said the wrong thing
# ============================================================================


# `network_config`'s refusal is covered behaviourally, not here:
# `tests/unit/test_network_config.py::TestConfigAgentBridgeRetirement
# ::test_apply_live_refuses_a_controller_without_revealing_secrets` calls the
# real endpoint and asserts the refusal text, that it does not blame missing
# credentials, and that `reveal_credentials` was never awaited. Asserting the
# same things against the module's source text here would be a weaker copy of
# a test that already exists.


# ============================================================================
# The four that had nothing to gate
# ============================================================================


class TestTheInventoryDomainsStayDeviceFree:
    """`router_agent`, `device_sync`, `hotspot` and `firewall` need no
    vendor gate for one reason only: they never talk to a device. That is a
    property of today's code, not a law, so it is asserted rather than
    recorded in a comment -- if someone later adds a device push to one of
    them, this fails and the vendor question gets asked at that moment
    instead of shipping as another surface that reports a working venue as
    a broken MikroTik.
    """

    DOMAINS = ("router_agent", "device_sync", "hotspot", "firewall")

    # Importing any of these means reaching a real device: the vendored
    # gateway, the RouterOS client, or this platform's own push helpers.
    DEVICE_REACHING_ROOTS = {
        "wyfy_device_gateway",
        "librouteros",
        "asyncssh",
        "paramiko",
    }
    DEVICE_REACHING_MODULES = {
        "app.domains.router.device_adapters",
    }

    @pytest.mark.parametrize("domain", DOMAINS)
    def test_the_domain_imports_nothing_that_reaches_a_device(
        self, domain: str
    ) -> None:
        offenders: list[str] = []
        for path in sorted(pathlib.Path(f"app/domains/{domain}").rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            imported: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported += [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            for module in imported:
                if module.split(".")[0] in self.DEVICE_REACHING_ROOTS:
                    offenders.append(f"{path}: {module}")
                if module in self.DEVICE_REACHING_MODULES:
                    offenders.append(f"{path}: {module}")
        assert not offenders, (
            f"{domain} now reaches a device: {offenders}. It therefore needs a "
            "vendor gate -- a controller-managed row cannot be pushed to. See "
            "app.domains.router.vendor_capabilities."
        )


class TestTheAuditIsAnchoredToTheRealVendorSet:
    """If the fleet vendor string ever drifts from what the gates compare
    against, every assertion in this file passes while gating nothing."""

    def test_the_gates_and_the_integration_domain_agree(self) -> None:
        from app.domains.network_integration.constants import (
            ROUTER_VENDOR_BY_PROVIDER,
        )

        for vendor in ROUTER_VENDOR_BY_PROVIDER.values():
            assert is_controller_managed(vendor), vendor
            with pytest.raises(WireGuardVendorNotSupportedError):
                validate_router_eligible_for_wireguard(_Row(vendor=vendor))

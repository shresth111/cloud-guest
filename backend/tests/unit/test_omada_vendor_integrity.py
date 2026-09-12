"""The vendor column stops being a one-click, unaudited, unguarded write.

On 2026-09-10 seven live MikroTiks had ``routers.vendor`` set to
``tplink_omada`` from a dropdown with no confirmation step, through an
organization-scoped endpoint every venue owner can reach. The audit trail
recorded that *something* was updated and nothing about what. One of the
seven -- ``Office Guest``, an RB750r2 -- went offline four days later and
nobody was told, because the alert evaluator's roster was filtered by the
label.

Four separable failures, and this module pins each:

* the label outranked the evidence (``TestEvidenceBeatsTheLabel``);
* the write was org-scoped, reasonless and refusable by nothing
  (``TestVendorIsAGuardedWrite``, ``TestTheVendorRouteIsMasterOnly``);
* the audit entry could not be *read* even once it was written
  (``TestAuditMetadataIsReadable``);
* device domains accepted work for a controller and refused it later, in
  vendor jargon, after a row was already written
  (``TestDeviceDomainsRefuseEarly``).
"""

from __future__ import annotations

import ast
import pathlib
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
    ensure_not_controller_managed,
    unsupported_vendor_message,
)
from app.domains.router.exceptions import (
    RouterVendorChangeRefusedError,
    RouterVendorNotSupportedError,
)
from app.domains.router.schemas import RouterUpdateRequest, RouterVendorChangeRequest
from app.domains.router.vendor_capabilities import (
    AGENT_EVIDENCE_FIELDS,
    SUPPORTED_ROUTER_VENDORS,
    agent_managed_rows,
    has_agent_evidence,
    is_agent_managed_row,
    is_controller_managed,
    is_controller_managed_row,
    looks_like_mikrotik_hardware,
    supports_zero_touch_provisioning,
    vendor_claim_is_contradicted,
)

from .test_router import FakeRouterRepository, make_router, make_service

pytestmark = pytest.mark.asyncio

_OMADA = "tplink_omada"
_BACKEND = pathlib.Path(__file__).resolve().parents[2]


def _clean_controller(**overrides: object) -> SimpleNamespace:
    """A row shaped like a controller `create_integration_with_fleet_device`
    actually writes: no heartbeat, no RouterOS version, no health check, no
    API credential."""
    fields: dict[str, object] = {
        "vendor": _OMADA,
        "name": "Lobby controller",
        "model": "OC200",
    }
    fields.update(dict.fromkeys(AGENT_EVIDENCE_FIELDS))
    fields.update(overrides)
    return SimpleNamespace(**fields)


# ============================================================================
# The predicate
# ============================================================================


class TestEvidenceBeatsTheLabel:
    def test_a_genuine_controller_is_controller_managed(self) -> None:
        assert is_controller_managed_row(_clean_controller()) is True
        assert is_agent_managed_row(_clean_controller()) is False
        assert has_agent_evidence(_clean_controller()) is False

    @pytest.mark.parametrize("field", AGENT_EVIDENCE_FIELDS)
    def test_any_single_piece_of_agent_evidence_overrides_the_label(
        self, field: str
    ) -> None:
        """Each column on its own is enough. A row that heartbeated, or
        reported a RouterOS version, or was health-checked, or holds RouterOS
        API credentials has behaved like one of ours -- and none of those
        things can happen to a controller."""
        row = _clean_controller(**{field: "set"})

        assert has_agent_evidence(row) is True
        assert is_controller_managed_row(row) is False
        assert vendor_claim_is_contradicted(row) is True

    def test_office_guest_stays_in_the_alert_roster(self) -> None:
        """The exact production row, and the exact function that dropped it.

        `Office Guest` is an RB750r2 that had been checking in for months,
        relabelled `tplink_omada`, then demoted to offline/unhealthy by the
        heartbeat sweep -- with no alert, because `agent_managed_rows` read
        the label. A device that checked in and then stopped is down, whatever
        somebody typed into a dropdown afterwards."""
        office_guest = _clean_controller(
            name="Office Guest",
            model="MikroTik hEX lite (RB750r2)",
            last_seen_at=datetime(2026, 9, 10, 8, 20, 27, tzinfo=UTC),
            api_credentials_encrypted="gAAAAA...",
        )

        assert agent_managed_rows([office_guest]) == [office_guest]
        assert supports_zero_touch_provisioning(office_guest) is True

    def test_a_real_controller_is_still_kept_out_of_the_roster(self) -> None:
        """The predicate must not have simply stopped filtering."""
        assert agent_managed_rows([_clean_controller()]) == []
        assert supports_zero_touch_provisioning(_clean_controller()) is False

    def test_a_bare_vendor_string_degrades_to_the_label(self) -> None:
        """A caller holding only a vendor string has no row and so no
        evidence; absence of evidence must not read as evidence of absence."""
        assert is_controller_managed_row(_OMADA) is True
        assert is_controller_managed_row("mikrotik") is False

    def test_the_label_predicate_is_untouched(self) -> None:
        """`is_controller_managed` still answers the pure-vendor question the
        adapter registries ask -- the two must not have been collapsed."""
        assert is_controller_managed(_clean_controller(last_seen_at="x")) is True

    @pytest.mark.parametrize(
        "model",
        ["MikroTik hEX lite (RB750r2)", "RB4011", "hAP ac2", "CCR2004-1G-12S+2XS"],
    )
    def test_mikrotik_hardware_is_recognised_from_the_model_string(
        self, model: str
    ) -> None:
        assert looks_like_mikrotik_hardware(model) is True

    @pytest.mark.parametrize("model", ["OC200", "OC300", "", None])
    def test_controller_hardware_is_not_mistaken_for_mikrotik(self, model) -> None:
        assert looks_like_mikrotik_hardware(model) is False


# ============================================================================
# The write
# ============================================================================


class TestVendorIsAGuardedWrite:
    def test_vendor_is_gone_from_the_org_scoped_update_schema(self) -> None:
        """`PUT /routers/{id}` is `routers.update` at ORGANIZATION scope,
        which every `organization-owner` holds in full. While `vendor` lived
        on this schema, any venue owner could relabel their own device."""
        assert "vendor" not in RouterUpdateRequest.model_fields

    def test_an_org_scoped_update_cannot_smuggle_a_vendor_through(self) -> None:
        """Pydantic's default is to ignore unknown fields, so the absence of
        the field is only half the guarantee: the value must also not survive
        `model_dump(exclude_unset=True)` into the service's update payload."""
        payload = RouterUpdateRequest.model_validate({"name": "x", "vendor": _OMADA})

        assert "vendor" not in payload.model_dump(exclude_unset=True)

    def test_a_reason_is_required(self) -> None:
        with pytest.raises(ValueError):
            RouterVendorChangeRequest(vendor="mikrotik", reason="")

    def test_the_override_is_off_unless_asked_for(self) -> None:
        request = RouterVendorChangeRequest(
            vendor="mikrotik", reason="corrective relabel"
        )

        assert request.override_contradicting_evidence is False

    async def test_an_unimplemented_vendor_is_refused(self) -> None:
        """`routers.vendor` is free text and everything outside
        CONTROLLER_MANAGED_VENDORS reads as an agent-managed MikroTik, so
        writing "unifi" would not record "unsupported" -- it would promise an
        agent is running on a UniFi controller."""
        service, repo, locations, orgs, _audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"

        with pytest.raises(RouterVendorNotSupportedError) as exc:
            await service.change_router_vendor(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                vendor="unifi",
                reason="the box says UniFi",
            )

        assert exc.value.status_code == 422
        assert "unifi" in exc.value.message
        assert router.vendor == "mikrotik"

    def test_the_supported_vocabulary_is_only_what_is_implemented(self) -> None:
        assert SUPPORTED_ROUTER_VENDORS == ("mikrotik", "tplink_omada")

    async def test_agent_evidence_refuses_a_controller_claim(self) -> None:
        service, repo, locations, orgs, audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        router.last_seen_at = datetime.now(UTC)

        with pytest.raises(RouterVendorChangeRefusedError) as exc:
            await service.change_router_vendor(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                vendor=_OMADA,
                reason="switching this venue to Omada",
            )

        assert exc.value.status_code == 422
        # The refusal names the evidence. A refusal that does not say what
        # the device claimed about itself is one an operator routes around.
        assert "last_seen_at" in exc.value.message
        assert "override_contradicting_evidence" in exc.value.message
        assert router.vendor == "mikrotik"
        assert audit.entries == []

    async def test_a_mikrotik_model_string_refuses_a_controller_claim(self) -> None:
        service, repo, locations, orgs, _audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        router.model = "MikroTik hEX lite (RB750r2)"

        with pytest.raises(RouterVendorChangeRefusedError) as exc:
            await service.change_router_vendor(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                vendor=_OMADA,
                reason="operator believes this is a controller",
            )

        assert "RB750r2" in exc.value.message

    async def test_the_override_is_possible_and_is_recorded(self) -> None:
        """A refusal with no way past it is one people work around with a
        manual UPDATE, which is worse than an audited override."""
        service, repo, locations, orgs, audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        router.last_seen_at = datetime.now(UTC)

        updated = await service.change_router_vendor(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            vendor=_OMADA,
            reason="hardware genuinely swapped for an OC200 on site",
            override_contradicting_evidence=True,
        )

        assert updated.vendor == _OMADA
        entry = audit.entries[-1]
        assert entry["event_metadata"]["changes"]["evidence_overridden"]
        assert "overridden" in entry["description"]

    async def test_a_live_integration_is_never_overridable(self) -> None:
        """Not evidence about the device but a dependency on the value: the
        integration's provider chose the vendor string, and
        `guest_sessions.router_id` is NOT NULL."""
        repo = FakeRouterRepository()
        service, repo, locations, orgs, _audit = make_service(repo=repo)
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        repo.integration_counts[router.id] = 1

        with pytest.raises(RouterVendorChangeRefusedError) as exc:
            await service.change_router_vendor(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                vendor=_OMADA,
                reason="tidying up",
                override_contradicting_evidence=True,
            )

        assert "integration" in exc.value.message
        assert router.vendor == "mikrotik"

    async def test_the_corrective_direction_is_not_refused(self) -> None:
        """All seven damaged rows carry agent evidence. Requiring an override
        to set them back to `mikrotik` would ask the operator to overrule the
        very evidence proving them right."""
        service, repo, locations, orgs, audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        router.vendor = _OMADA
        router.last_seen_at = datetime.now(UTC)
        router.model = "MikroTik hEX lite (RB750r2)"

        updated = await service.change_router_vendor(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            vendor="mikrotik",
            reason="reverting the 2026-09-10 mislabel; RB750r2 with heartbeats",
        )

        assert updated.vendor == "mikrotik"
        changes = audit.entries[-1]["event_metadata"]["changes"]
        assert changes["vendor"] == {"from": _OMADA, "to": "mikrotik"}
        assert "evidence_overridden" not in changes

    async def test_the_audit_entry_carries_the_diff_and_the_reason(self) -> None:
        """The whole point. Seven relabels could not be reconstructed because
        every router update wrote a byte-identical `Router 'X' updated` row
        with `{}` metadata."""
        service, repo, locations, orgs, audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"
        reason = "venue migrated to an Omada controller, ticket WG-4471"
        router.model = "OC200"

        await service.change_router_vendor(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            vendor=_OMADA,
            reason=reason,
        )

        entry = audit.entries[-1]
        assert entry["event_metadata"]["changes"]["vendor"] == {
            "from": "mikrotik",
            "to": _OMADA,
        }
        assert entry["event_metadata"]["changes"]["reason"] == reason
        assert "mikrotik -> tplink_omada" in entry["description"]
        assert reason in entry["description"]

    async def test_a_no_op_writes_no_audit_entry(self) -> None:
        """A replayed request is not a change, and an entry claiming one is
        the same dishonesty in the other direction."""
        service, repo, locations, orgs, audit = make_service()
        organization = orgs.add()
        location = locations.add(organization_id=organization.id)
        router = await make_router(
            repo, location_id=location.id, organization_id=organization.id
        )
        # `FakeRouterRepository` never flushes, so the column's "mikrotik"
        # default is not applied for it -- set the starting point explicitly
        # rather than depending on an ORM default that only exists in
        # PostgreSQL.
        router.vendor = "mikrotik"

        await service.change_router_vendor(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            vendor="mikrotik",
            reason="no change intended",
        )

        assert audit.entries == []


class TestTheVendorRouteIsMasterOnly:
    def test_the_route_is_global_scoped_and_the_org_one_has_no_vendor(self) -> None:
        from app.domains.rbac.enums import ScopeType
        from app.main import create_app

        app = create_app()
        vendor_route = next(
            route
            for route in app.routes
            if getattr(route, "path", "")
            == "/api/v1/platform/routers/{router_id}/vendor"
        )
        closure_values = [
            cell.cell_contents
            for dependency in vendor_route.dependant.dependencies
            for cell in (dependency.call.__closure__ or ())
        ]

        assert "routers.update" in closure_values
        assert ScopeType.GLOBAL in closure_values


# ============================================================================
# The read
# ============================================================================


class TestAuditMetadataIsReadable:
    def test_the_response_schema_carries_metadata(self) -> None:
        """Fixing the writer without this fixes nothing anybody can see."""
        from app.domains.audit.schemas import AuditLogEntryResponse

        assert "event_metadata" in AuditLogEntryResponse.model_fields

    def test_an_entry_with_no_metadata_serialises_as_an_object(self) -> None:
        from app.domains.audit.schemas import AuditLogEntryResponse

        entry = AuditLogEntryResponse(
            id="1",
            actor_user_id=None,
            action="router.updated",
            entity_type="router",
            entity_id=None,
            description=None,
            organization_id=None,
            location_id=None,
            created_at=datetime.now(UTC),
        )

        assert entry.event_metadata == {}

    def test_the_csv_export_has_the_column_last(self) -> None:
        from app.domains.audit.constants import CSV_EXPORT_HEADERS

        assert CSV_EXPORT_HEADERS[-1] == "event_metadata"

    @pytest.mark.parametrize(
        "key",
        [
            "api_secret",
            "snmp_community_encrypted",
            "operator_password",
            "session_id",
            "omada_client_credential",
        ],
    )
    def test_secret_shaped_keys_never_leave_the_read_path(self, key: str) -> None:
        """`event_metadata` is written by every domain, including ones not
        yet written. The writer-side redaction stops a secret being stored;
        this stops one being served when a writer forgets."""
        from app.domains.audit.redaction import (
            REDACTED_PLACEHOLDER,
            redact_event_metadata,
        )

        out = redact_event_metadata({"changes": {key: {"from": "a", "to": "b"}}})

        assert out["changes"][key] == REDACTED_PLACEHOLDER

    def test_a_whole_subtree_is_redacted_not_just_its_leaves(self) -> None:
        from app.domains.audit.redaction import (
            REDACTED_PLACEHOLDER,
            redact_event_metadata,
        )

        out = redact_event_metadata(
            {"credentials": {"username": "admin", "password": "hunter2"}}
        )

        assert out == {"credentials": REDACTED_PLACEHOLDER}

    def test_ordinary_values_pass_through_untouched(self) -> None:
        from app.domains.audit.redaction import redact_event_metadata

        changes = {"changes": {"vendor": {"from": "mikrotik", "to": _OMADA}}}

        assert redact_event_metadata(changes) == changes

    def test_absurd_nesting_fails_closed(self) -> None:
        """`event_metadata` is unbounded free-form JSONB on a paginated list
        endpoint; the depth bound has to exist and has to redact rather than
        pass through."""
        from app.domains.audit.redaction import (
            REDACTED_PLACEHOLDER,
            redact_event_metadata,
        )

        deep: object = "leaf"
        for _ in range(50):
            deep = {"a": deep}

        rendered = repr(redact_event_metadata(deep))

        assert REDACTED_PLACEHOLDER in rendered
        assert "leaf" not in rendered


# ============================================================================
# The refusals
# ============================================================================


#: Every service function that must refuse a controller-managed row before it
#: writes anything, decrypts anything, enqueues anything or dials a device.
#:
#: Checked structurally as well as behaviourally: a behavioural test proves
#: today's call refuses, and this proves nobody quietly adds a ninth write
#: path without one. The audit that produced this list found that `vlan`,
#: `dhcp`, `port_forwarding`, `qos`, `queue_management`, `hotspot`,
#: `firewall` and `provisioning_engine` all wrote their row and returned 201,
#: and that `network_config.push_isf_netwatch_config` rotated a real agent
#: credential first.
GATED_WRITE_PATHS: tuple[tuple[str, str], ...] = (
    ("vlan", "create_vlan"),
    ("dhcp", "create_pool"),
    ("port_forwarding", "create_rule"),
    ("qos", "create_rule"),
    ("queue_management", "create_assignment"),
    ("hotspot", "create_profile"),
    ("firewall", "create_rule"),
    ("provisioning_engine", "create_job"),
    ("provisioning_engine", "execute_console_command"),
    ("provisioning_engine", "discover_device"),
    ("network_diagnostics", "_execute"),
)


def _function_source(domain: str, function: str) -> str:
    path = _BACKEND / "app" / "domains" / domain / "service.py"
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
            and node.name == function
        ):
            return ast.get_source_segment(path.read_text(), node) or ""
    raise AssertionError(f"{domain}.{function} not found")


class TestDeviceDomainsRefuseEarly:
    @pytest.mark.parametrize(("domain", "function"), GATED_WRITE_PATHS)
    def test_every_device_write_path_asks_the_vendor_question(
        self, domain: str, function: str
    ) -> None:
        assert "ensure_not_controller_managed(" in _function_source(domain, function)

    @pytest.mark.parametrize(("domain", "function"), GATED_WRITE_PATHS)
    def test_the_gate_comes_before_the_credentials_and_the_write(
        self, domain: str, function: str
    ) -> None:
        """Ordering is the whole point: the adapter registries already refused
        this vendor, but only after the row existed or after the credential
        branch had told a venue owner to go and add credentials for a device
        that will never accept any."""
        source = _function_source(domain, function)
        gate = source.index("ensure_not_controller_managed(")
        for later in (
            "_resolve_device_credentials(",
            "_resolve_credentials(",
            "repository.create_",
            "self.repository.create_assignment(",
        ):
            if later in source:
                assert gate < source.index(later), (
                    f"{domain}.{function}: the vendor gate runs after {later}"
                )

    def test_the_network_config_write_paths_are_gated(self) -> None:
        for function in (
            "push_config",
            "push_isp_netwatch_config",
            "push_basic_wan_config",
            "rollback_and_apply",
        ):
            assert "_refuse_if_controller_managed(" in _function_source(
                "network_config", function
            ) or "ensure_not_controller_managed(" in _function_source(
                "network_config", function
            )

    def test_the_netwatch_gate_precedes_the_credential_mint(self) -> None:
        """The single worst ordering found: a controller row was minted a real
        plaintext agent bearer credential -- for a device that runs no agent
        and can never present it -- before two rows were written for a push
        that could not land."""
        source = _function_source("network_config", "push_isp_netwatch_config")

        mint = "issue_credential = self.agent_credential_issuer"

        assert source.index("ensure_not_controller_managed(") < source.index(mint)

    def test_the_wireguard_register_path_finally_checks_eligibility(self) -> None:
        """The one write path in that domain that skipped
        `validate_router_eligible_for_wireguard`. A peer registered for a
        controller permanently occupies a /24 and is indistinguishable from a
        device someone never finished setting up -- the hub agent has no
        delete verb."""
        source = _function_source("wireguard", "register_agent_allocated_peer")

        assert "validate_router_eligible_for_wireguard(router)" in source

    def test_the_refusal_names_the_feature_and_the_equipment(self) -> None:
        with pytest.raises(ControllerManagedFeatureUnavailableError) as exc:
            ensure_not_controller_managed(
                _clean_controller(name="Office Guest"), feature="Port Forwarding"
            )

        message = exc.value.message
        assert exc.value.status_code == 422
        assert "Port Forwarding" in message
        assert "TP-Link Omada controller" in message
        assert "Office Guest" in message
        # No jargon reaches a duty manager.
        assert "adapter" not in message
        assert "vendor" not in message

    def test_an_agent_managed_row_passes_straight_through(self) -> None:
        ensure_not_controller_managed(
            SimpleNamespace(vendor="mikrotik", name="Front Desk"), feature="VLAN"
        )

    def test_a_mislabelled_row_is_still_refused_by_the_gate(self) -> None:
        """The gate asks the LABEL, unlike the monitoring predicates. A row
        mislabelled towards a controller is exactly the case where we should
        decline to push configuration until somebody says what it really is;
        over-refusing costs a sentence, under-refusing costs a credential
        rotation against the wrong device."""
        mislabelled = _clean_controller(last_seen_at=datetime.now(UTC))

        with pytest.raises(ControllerManagedFeatureUnavailableError):
            ensure_not_controller_managed(mislabelled, feature="Network Zones")

    def test_the_registry_message_is_rewritten_for_a_controller(self) -> None:
        message = unsupported_vendor_message(feature="Network Zones", vendor=_OMADA)

        assert "TP-Link Omada controller" in message
        assert "adapter" not in message

    def test_an_unrecognised_vendor_keeps_the_engineer_facing_wording(self) -> None:
        """`Router.vendor` is free text, and a row carrying "MikroTik"
        capitalised is a data problem, not a customer's controller. Naming the
        exact string is the useful thing to say there."""
        message = unsupported_vendor_message(feature="Network Zones", vendor="MikroTik")

        assert "'MikroTik'" in message

    def test_all_seven_registries_use_the_shared_message(self) -> None:
        for domain in (
            "vlan",
            "dhcp",
            "port_forwarding",
            "qos",
            "queue_management",
            "network_diagnostics",
            "provisioning_engine",
        ):
            path = _BACKEND / "app" / "domains" / domain / "exceptions.py"
            source = path.read_text()
            assert "unsupported_vendor_message(" in source, domain


# ============================================================================
# The 403 a venue owner reads, and the row it should have left behind
# ============================================================================


class TestGlobalScopeDenialsAreLegible:
    def test_a_global_denial_says_what_to_do_instead(self) -> None:
        """`POST /network-integrations/platform/onboard` is GLOBAL-scoped and
        an ORGANIZATION grant can never satisfy it, whatever
        `X-Organization-Id` is sent -- so for a venue account the bare message
        invited exactly the two useless responses: switch organization and
        retry, or ask to be granted the permission."""
        from app.domains.rbac.exceptions import PermissionDeniedError

        message = PermissionDeniedError(
            "network_integrations.create", "global scope"
        ).message

        assert "platform operator" in message
        assert "will not change that" in message

    def test_an_organization_scoped_denial_is_unchanged(self) -> None:
        """The guidance is true only of GLOBAL checks. An org-scoped denial
        often IS fixable by a grant, and telling that caller to give up would
        be a new wrong answer."""
        from app.domains.rbac.exceptions import PermissionDeniedError

        message = PermissionDeniedError(
            "routers.update", "organization scope (abc)"
        ).message

        assert "platform operator" not in message


class TestDeniedAttemptsLeaveATrace:
    async def test_the_denial_row_is_not_written_on_the_request_session(self) -> None:
        """`AccessValidator.check` created the PERMISSION_DENIED row and then
        raised; `get_db_session` rolls back on any exception, so every denied
        request in this platform's history left no persisted trace at all.

        The row must therefore be written somewhere the rollback cannot
        reach."""
        from app.domains.rbac.authorization import AccessValidator
        from app.domains.rbac.exceptions import PermissionDeniedError

        from .test_rbac import FakeRBACRepository

        request_session_repo = FakeRBACRepository()
        durable_repo = FakeRBACRepository()

        @asynccontextmanager
        async def durable():
            yield durable_repo

        validator = AccessValidator(
            request_session_repo, denial_audit_repository=durable
        )

        with pytest.raises(PermissionDeniedError):
            await validator.check(uuid.uuid4(), "routers.delete")

        assert request_session_repo.audit_log_rows == []
        assert any(
            row.action == "permission_denied" for row in durable_repo.audit_log_rows
        )


# ============================================================================
# Tunnel internals never reach a venue-owner payload
# ============================================================================


class TestTunnelInternalsStayOffCustomerPayloads:
    def test_the_management_tunnel_is_stripped(self) -> None:
        """`wg-cloudguard` was being served on `GET /health-history` --
        `router_provisioning.read` at ORGANIZATION scope -- next to ether1-5
        and bridge, with byte counters, as a working interface."""
        from app.domains.router_provisioning.customer_visibility import (
            customer_visible_interface_counters,
        )

        counters = [
            {"if_index": 1, "if_name": "ether1", "up": True, "in_octets": 10},
            {
                "if_index": 9,
                "if_name": "wg-cloudguard",
                "up": True,
                "in_octets": 264192,
                "out_octets": 646144,
            },
            {"if_index": 2, "if_name": "bridge", "up": True},
        ]

        visible = customer_visible_interface_counters(counters)

        assert [c["if_name"] for c in visible] == ["ether1", "bridge"]

    def test_the_response_builder_applies_the_filter(self) -> None:
        """The filter has to be where the payload is built, not only in the
        console: a field the API sends and a client declines to draw is still
        in the JSON, in proxy logs, and in whatever consumes it next."""
        source = (
            _BACKEND / "app" / "domains" / "router_provisioning" / "router.py"
        ).read_text()
        builder = source[source.index("def _health_snapshot_response(") :]
        builder = builder[: builder.index("\ndef ")]

        assert "customer_visible_interface_counters(" in builder
        assert "interface_traffic_counters=snapshot.interface" not in builder

    def test_the_filter_matches_the_name_the_renderer_actually_writes(self) -> None:
        """The prefix families are restated here rather than imported from
        `network_config.renderers`, so this is what stops them drifting: the
        literal the bootstrap script really creates must be caught."""
        from app.domains.network_config.renderers import WIREGUARD_INTERFACE_NAME
        from app.domains.router_provisioning.customer_visibility import (
            is_platform_tunnel_interface,
        )

        assert is_platform_tunnel_interface(WIREGUARD_INTERFACE_NAME) is True

    @pytest.mark.parametrize(
        "if_name", ["ether1", "ether5", "bridge", "wlan1", "vlan100", "sfp-sfpplus1"]
    )
    def test_the_venues_own_interfaces_are_untouched(self, if_name: str) -> None:
        from app.domains.router_provisioning.customer_visibility import (
            is_platform_tunnel_interface,
        )

        assert is_platform_tunnel_interface(if_name) is False

    def test_none_is_not_flattened_to_an_empty_list(self) -> None:
        """`None` means "no SNMP reading at all"; `[]` means "SNMP answered
        and reported nothing". Collapsing the first into the second is the
        fabricated zero this schema already refuses elsewhere."""
        from app.domains.router_provisioning.customer_visibility import (
            customer_visible_interface_counters,
        )

        assert customer_visible_interface_counters(None) is None
        assert customer_visible_interface_counters([]) == []


# ============================================================================
# Suspension means something to writes
# ============================================================================


class TestSuspendedTenantsGetNoNewService:
    async def test_a_new_location_is_refused(self) -> None:
        """`QA Test Co` was `suspended` in production and
        `POST /organizations/{id}/locations` still returned 201 -- a live
        venue under an account whose service is stopped, with no warning
        before, during or after."""
        from app.domains.organization.enums import OrganizationStatus
        from app.domains.organization.exceptions import (
            OrganizationSuspendedNewServiceError,
        )

        from .test_location import make_service as make_location_service

        service, _repo, org_lookup, _audit = make_location_service()
        organization = org_lookup.add(status=OrganizationStatus.SUSPENDED.value)

        with pytest.raises(OrganizationSuspendedNewServiceError) as exc:
            await service.create_location(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                requesting_organization_id=organization.id,
                name="New Venue",
                slug="new-venue",
                address_line1="1 Road",
                city="Pune",
                state_province="MH",
                postal_code="411001",
                country="IN",
            )

        assert exc.value.status_code == 409
        assert "suspended" in exc.value.message
        # It tells the operator what is and is not blocked, and how to
        # proceed if the creation really was intended.
        assert "editable" in exc.value.message
        assert "Reinstate" in exc.value.message

    async def test_an_active_tenant_is_unaffected(self) -> None:
        from .test_location import make_service as make_location_service

        service, _repo, org_lookup, _audit = make_location_service()
        organization = org_lookup.add()

        location = await service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=organization.id,
            name="New Venue",
            slug="new-venue",
            address_line1="1 Road",
            city="Pune",
            state_province="MH",
            postal_code="411001",
            country="IN",
        )

        assert location.name == "New Venue"

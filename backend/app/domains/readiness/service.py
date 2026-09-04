"""Core business logic for the Router Readiness Checklist domain.

``get_checklist`` is the read path every caller actually wants: it always
re-runs the five ``DetectionMode.AUTO`` items live (composing narrow reads
against ``router``/``isp``/``wireguard``/``router_agent`` -- zero new
device I/O, exactly the "what's checkable today, right now" set the
originating backend-engineer report scoped this domain to), persists each
result via ``ReadinessRepository.upsert_item`` so the row reflects "last
checked" honestly, then layers the nine ``DetectionMode.MANUAL`` items on
top from whatever is already stored (or a synthetic ``NOT_CHECKED`` default
if a router has never had one touched -- no phantom row is written for an
item nobody has looked at yet).

``confirm_item`` is the only way a human overrides any item -- auto or
manual -- recording ``detection_mode=MANUAL`` on that one row so the next
``get_checklist`` call (which only overwrites the five auto items) leaves
it alone. This matters most for ``WIREGUARD``: the auto-check honestly
cannot distinguish "no tunnel configured" from "broken tunnel" without a
human deciding "this router doesn't use WireGuard, mark it fine."

Each cross-domain dependency is a narrow ``Protocol`` satisfied by that
sibling domain's own service (composed via ``dependencies.py``, the same
"depend on the smallest interface the sibling's real service already
implements" convention every other domain in this codebase follows) --
except ``RouterAgentCredentialLookupProtocol``, which is satisfied by
``router_agent.RouterAgentService.get_credential_for_router`` (see that
method's own docstring for why it's a small, additive service-layer method
rather than this domain reaching into ``router_agent``'s repository
directly).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from .constants import (
    CHECKLIST_ITEMS,
    CHECKLIST_ITEMS_BY_KEY,
    FAILING_STATUSES,
    PASSING_STATUSES,
    ChecklistItemKey,
    ChecklistItemStatus,
    DetectionMode,
)
from .exceptions import UnknownChecklistItemError
from .models import RouterChecklistItem
from .repository import ReadinessRepositoryProtocol


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Any: ...


class IspLinkLookupProtocol(Protocol):
    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Any], Any]: ...


class WireGuardLookupProtocol(Protocol):
    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> Any: ...

    def compute_health_status(
        self, peer: Any, *, now: datetime | None = None
    ) -> Any: ...


class ConfigVersionLookupProtocol(Protocol):
    """The one read this domain needs from ``router_provisioning``: has any
    rendered configuration ever actually been applied to this router?

    Narrow on purpose, and satisfied by the real
    ``RouterProvisioningService.list_versions`` -- the same
    "smallest interface the sibling already implements" convention every
    other lookup in this module follows."""

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = ...,
        page_size: int = ...,
    ) -> tuple[list[Any], object]: ...


class RogueDhcpStatusLookupProtocol(Protocol):
    """The one read this domain needs from ``dhcp``: what did the last
    rogue-DHCP detection pass see on this router's interfaces?

    Satisfied by the real ``DhcpService.get_rogue_dhcp_statuses`` -- the
    same "smallest interface the sibling already implements" convention
    every other lookup in this module follows.

    **This read touches the database only.** That is a requirement of this
    Protocol, not an accident of its current implementation:
    ``get_checklist`` re-runs every AUTO item on every GET, so any
    collaborator here is on a hot request path. The device read that
    produced these rows happens on a six-hour schedule in
    ``app.domains.dhcp.tasks``, off the request path entirely. A future
    implementation that reached for a router here would silently put a
    RouterOS timeout behind a dashboard page load.

    No ``requesting_organization_id`` parameter, deliberately.
    ``get_checklist`` has already resolved the router through its own
    org-scoped ``router_lookup.get_router`` before ``_run_auto_detection``
    is reached, so authorization has happened. Passing an org id here that
    the implementation then ignored in favour of the router id would be the
    exact shape of the path-id scoping defect this codebase has found
    across a number of handlers: the permission check reads one thing and
    the query reads another.
    """

    async def get_rogue_dhcp_statuses(self, router_id: uuid.UUID) -> list[Any]: ...


class RouterAgentCredentialLookupProtocol(Protocol):
    async def get_credential_for_router(self, router_id: uuid.UUID) -> Any | None: ...


class ReadinessService:
    """Core readiness-checklist business logic."""

    def __init__(
        self,
        repository: ReadinessRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        isp_lookup: IspLinkLookupProtocol,
        wireguard_lookup: WireGuardLookupProtocol,
        router_agent_lookup: RouterAgentCredentialLookupProtocol,
        config_version_lookup: ConfigVersionLookupProtocol | None = None,
        rogue_dhcp_lookup: RogueDhcpStatusLookupProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.isp_lookup = isp_lookup
        self.wireguard_lookup = wireguard_lookup
        self.router_agent_lookup = router_agent_lookup
        # Optional so every existing construction of this service keeps
        # working unchanged; when absent, the guest-data-path check falls
        # back to the ISP-link evidence alone and says so rather than
        # silently passing.
        self.config_version_lookup = config_version_lookup
        # Optional for the same reason ``config_version_lookup`` above is:
        # every existing construction of this service keeps working
        # unchanged. When absent, ROGUE_DHCP_GUARD reports NOT_CHECKED and
        # says why, rather than silently passing a router nobody looked at.
        self.rogue_dhcp_lookup = rogue_dhcp_lookup

    # ========================================================================
    # Read path
    # ========================================================================

    async def get_checklist(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[RouterChecklistItem]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        auto_results = await self._run_auto_detection(
            router, requesting_organization_id=requesting_organization_id
        )
        stored_by_key = {
            row.item_key: row
            for row in await self.repository.get_all_for_router(router_id)
        }

        rows: list[RouterChecklistItem] = []
        for definition in CHECKLIST_ITEMS:
            key = definition.key.value
            if key in auto_results:
                status_value, detail, evidence = auto_results[key]
                row = await self.repository.upsert_item(
                    router_id,
                    key,
                    {
                        "status": status_value.value,
                        "detection_mode": DetectionMode.AUTO.value,
                        "detail": detail,
                        "evidence": evidence,
                        "last_checked_at": datetime.now(UTC),
                        "checked_by_user_id": None,
                    },
                )
                rows.append(row)
            elif key in stored_by_key:
                rows.append(stored_by_key[key])
            else:
                rows.append(
                    RouterChecklistItem(
                        router_id=router_id,
                        item_key=key,
                        status=ChecklistItemStatus.NOT_CHECKED.value,
                        detection_mode=definition.detection_mode.value,
                        detail=None,
                        evidence={},
                        last_checked_at=None,
                        checked_by_user_id=None,
                    )
                )
        return rows

    def summarize(self, rows: list[RouterChecklistItem]) -> dict[str, int]:
        passing = sum(1 for r in rows if r.status in _values(PASSING_STATUSES))
        failing = sum(1 for r in rows if r.status in _values(FAILING_STATUSES))
        not_checked = sum(
            1 for r in rows if r.status == ChecklistItemStatus.NOT_CHECKED.value
        )
        return {
            "total": len(rows),
            "passing": passing,
            "failing": failing,
            "not_checked": not_checked,
        }

    # ========================================================================
    # Write path -- manual confirm/override
    # ========================================================================

    async def confirm_item(
        self,
        router_id: uuid.UUID,
        item_key: str,
        *,
        status: ChecklistItemStatus,
        detail: str | None,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> RouterChecklistItem:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if item_key not in CHECKLIST_ITEMS_BY_KEY:
            raise UnknownChecklistItemError(item_key)
        return await self.repository.upsert_item(
            router_id,
            item_key,
            {
                "status": status.value,
                "detection_mode": DetectionMode.MANUAL.value,
                "detail": detail,
                "evidence": {},
                "last_checked_at": datetime.now(UTC),
                "checked_by_user_id": actor_user_id,
            },
        )

    # ========================================================================
    # Auto-detection -- the five zero-new-I/O items
    # ========================================================================

    async def _run_auto_detection(
        self, router: Any, *, requesting_organization_id: uuid.UUID | None
    ) -> dict[str, tuple[ChecklistItemStatus, str, dict[str, Any]]]:
        results: dict[str, tuple[ChecklistItemStatus, str, dict[str, Any]]] = {}
        results[ChecklistItemKey.HEARTBEAT.value] = self._check_heartbeat(router)
        results[ChecklistItemKey.SAAS_PROVISIONING.value] = (
            await self._check_saas_provisioning(router)
        )
        results[ChecklistItemKey.WAN_CONNECTIVITY.value] = (
            await self._check_wan_connectivity(
                router, requesting_organization_id=requesting_organization_id
            )
        )
        results[ChecklistItemKey.GUEST_DATA_PATH.value] = (
            await self._check_guest_data_path(
                router, requesting_organization_id=requesting_organization_id
            )
        )
        results[ChecklistItemKey.WIREGUARD.value] = await self._check_wireguard(
            router, requesting_organization_id=requesting_organization_id
        )
        results[ChecklistItemKey.API_REACHABILITY.value] = self._check_api_reachability(
            router
        )
        results[ChecklistItemKey.ROGUE_DHCP_GUARD.value] = (
            await self._check_rogue_dhcp_detection(router)
        )
        return results

    def _check_heartbeat(
        self, router: Any
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        # Coarse today -- online/offline straight from Router.status, the
        # same live signal Master Console's own router list already
        # displays. A staleness-window refinement (comparing
        # ``last_seen_at`` against a threshold even while ``status`` still
        # reads ONLINE) is a reasonable future improvement, not required
        # for an honest first pass.
        status = str(getattr(router, "status", "") or "")
        last_seen_at = getattr(router, "last_seen_at", None)
        evidence = {
            "router_status": status,
            "last_seen_at": last_seen_at.isoformat() if last_seen_at else None,
        }
        if status == "online":
            return (ChecklistItemStatus.PASS, "Router is online.", evidence)
        if last_seen_at is None:
            return (
                ChecklistItemStatus.FAIL,
                "This router has never checked in.",
                evidence,
            )
        return (
            ChecklistItemStatus.FAIL,
            f"Router status is '{status}', not online.",
            evidence,
        )

    async def _check_saas_provisioning(
        self, router: Any
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        credential = await self.router_agent_lookup.get_credential_for_router(router.id)
        if credential is None:
            return (
                ChecklistItemStatus.FAIL,
                "No platform agent credential has ever been issued for this router.",
                {"credential_issued": False},
            )
        now = datetime.now(UTC)
        active = credential.is_active(now=now)
        evidence = {
            "credential_issued": True,
            "revoked_at": credential.revoked_at.isoformat()
            if credential.revoked_at
            else None,
            "expires_at": credential.expires_at.isoformat(),
        }
        if active and str(getattr(router, "status", "")) == "online":
            return (ChecklistItemStatus.PASS, "Agent credential is active.", evidence)
        if not active:
            return (
                ChecklistItemStatus.FAIL,
                "The agent credential is expired or revoked.",
                evidence,
            )
        return (
            ChecklistItemStatus.FAIL,
            "Agent credential is active, but the router is not currently online.",
            evidence,
        )

    async def _check_wan_connectivity(
        self, router: Any, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        links, _meta = await self.isp_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router.id,
            page=1,
            page_size=50,
        )
        enabled = [link for link in links if getattr(link, "is_enabled", False)]
        if not enabled:
            return (
                ChecklistItemStatus.NOT_CHECKED,
                "No enabled WAN links are configured yet.",
                {"enabled_link_count": 0},
            )
        evidence = {
            "enabled_link_count": len(enabled),
            "health_statuses": [
                getattr(link, "health_status", None) for link in enabled
            ],
        }
        if any(getattr(link, "health_status", None) == "healthy" for link in enabled):
            return (
                ChecklistItemStatus.PASS,
                "At least one enabled WAN link is healthy.",
                evidence,
            )
        return (
            ChecklistItemStatus.FAIL,
            "No enabled WAN link is currently passing its health check.",
            evidence,
        )

    async def _check_guest_data_path(
        self, router: Any, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        """Has the platform ever asserted a route to the internet for this
        router's guests?

        FAIL, not NOT_CHECKED, when the answer is no. That distinction is
        the entire point of this item. ``_check_wan_connectivity`` above
        returns NOT_CHECKED for a router with no enabled ISP link, which is
        right for a question about link health and is why nothing caught
        the 2026-08-27 fault: NOT_CHECKED is absent from FAILING_STATUSES,
        so "this router has no data path whatsoever" was summarised as
        nothing being wrong. A venue that cannot serve a single guest is
        not an unanswered question, it is a failure.

        Two independent kinds of evidence, either of which is enough:

        * an **enabled ISP link**, which is what makes
          ``wan.assembler.render_basic_wan_config`` emit anything at all
          (it short-circuits on ``if not ctx.links``), and with it the
          discovered-uplink masquerade; or
        * an **applied config version**, which means a rendered script --
          now always carrying ``render_guest_data_path`` -- actually
          reached the device.

        Deliberately does NOT count a completed bootstrap as evidence, even
        though the bootstrap script now asserts the data path itself. The
        platform records that a router checked in, not which revision of
        the script it ran, so treating enrollment as proof would be
        inferring a fact from something that does not carry it -- the same
        move that produced every other failure this week. If that becomes
        the common case, the honest fix is for the device to report the
        assertion, not for this check to assume it.
        """
        links, _meta = await self.isp_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router.id,
            page=1,
            page_size=50,
        )
        enabled_links = [
            link for link in links if getattr(link, "is_enabled", False)
        ]
        applied_versions: list[Any] = []
        lookup_available = self.config_version_lookup is not None
        if lookup_available:
            versions, _vmeta = await self.config_version_lookup.list_versions(
                router_id=router.id,
                requesting_organization_id=requesting_organization_id,
                page=1,
                page_size=50,
            )
            applied_versions = [
                version
                for version in versions
                if getattr(version, "status", None) == "applied"
            ]
        evidence = {
            "enabled_link_count": len(enabled_links),
            "applied_config_version_count": len(applied_versions),
            "config_version_lookup_available": lookup_available,
        }
        if enabled_links or applied_versions:
            return (
                ChecklistItemStatus.PASS,
                "A guest data path has been asserted for this router.",
                evidence,
            )
        return (
            ChecklistItemStatus.FAIL,
            (
                "No guest data path has ever been asserted for this router: "
                "it has no enabled WAN link and no applied config version. "
                "Guests will authenticate successfully and have no internet."
            ),
            evidence,
        )

    async def _check_rogue_dhcp_detection(
        self, router: Any
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        """Is this router watching for a DHCP server on the guest network
        that isn't ours?

        Reads only the rows ``app.domains.dhcp.tasks``'s scheduled detector
        persisted -- **no device I/O**, which is what allows an AUTO item
        sourced from a real device fact to live on a read path that re-runs
        on every GET. See ``RogueDhcpStatusLookupProtocol``.

        ## Three outcomes, and why ``unknown`` is not one of the failures

        * **FAIL** -- at least one interface where the device *answered*
          and the answer was "nothing is watching this". That covers both
          "no alert row at all" and "row present, ``enabled=False``" -- and
          the second is the one RouterOS's own default produces, a row that
          reads as configured in a ``/export`` and watches nothing.
        * **NOT_CHECKED** -- no row yet (the detector has not reached this
          router), or every row is ``unknown`` (it tried and could not get
          an answer). ``ChecklistItemStatus.NOT_CHECKED`` is absent from
          ``FAILING_STATUSES``, so this never counts against a venue.
        * **PASS** -- every interface answered, and every one is watched.

        A router the detector could not reach is **never** a FAIL. That is
        not a nicety: an unreachable router is an unanswered question, and
        answering it "unguarded" would raise a failure on every offline
        router in the fleet that no operator could act on -- while telling
        them nothing true about rogue DHCP. Same posture
        ``app.domains.monitoring.constants.HealthStatus.UNKNOWN`` documents
        for its own no-data-to-judge-from case; this codebase has been
        bitten by collapsing the two more than once.

        Note the ordering: a known-unguarded interface outranks an unknown
        one. If one interface answered "nothing watching" and another timed
        out, the failure is real and is reported -- it was established by a
        device that answered, and the unknown beside it does not soften it.

        ## Detection only

        Every string this method produces says detection, never protection.
        ``/ip dhcp-server alert`` logs and does nothing else -- see
        ``constants.CHECKLIST_ITEMS``'s own note on this item.
        """
        if self.rogue_dhcp_lookup is None:
            return (
                ChecklistItemStatus.NOT_CHECKED,
                "Rogue DHCP detection results are not available here.",
                {"lookup_available": False},
            )
        rows = await self.rogue_dhcp_lookup.get_rogue_dhcp_statuses(router.id)
        # Compared as plain strings rather than imported as an enum: this
        # domain composes ``dhcp`` through a duck-typed Protocol and never
        # imports its module, the same loose coupling every other lookup
        # here keeps. The values are ``app.domains.dhcp.constants
        # .RogueDhcpAlertState``.
        unguarded = [r for r in rows if getattr(r, "alert_state", None) == "unguarded"]
        unknown = [r for r in rows if getattr(r, "alert_state", None) == "unknown"]
        guarded = [r for r in rows if getattr(r, "alert_state", None) == "guarded"]
        last_checked = max(
            (r.checked_at for r in rows if getattr(r, "checked_at", None)),
            default=None,
        )
        evidence: dict[str, Any] = {
            "lookup_available": True,
            "interface_count": len(rows),
            "guarded_count": len(guarded),
            "unguarded_count": len(unguarded),
            "unknown_count": len(unknown),
            "unguarded_interfaces": [r.interface for r in unguarded],
            "last_checked_at": last_checked.isoformat() if last_checked else None,
        }
        if not rows:
            return (
                ChecklistItemStatus.NOT_CHECKED,
                "This router has not been checked for rogue DHCP detection yet.",
                evidence,
            )
        if unguarded:
            names = ", ".join(sorted(r.interface for r in unguarded))
            return (
                ChecklistItemStatus.FAIL,
                (
                    f"No rogue DHCP detection is active on: {names}. "
                    "These interfaces hand out addresses, so another DHCP "
                    "server on the segment would go unnoticed."
                ),
                evidence,
            )
        if unknown:
            # Deliberately NOT a FAIL. We did not learn anything about this
            # router; saying it is unwatched would be inventing a finding.
            return (
                ChecklistItemStatus.NOT_CHECKED,
                (
                    "The last check could not reach this router, so its "
                    "rogue DHCP detection state is unknown."
                ),
                evidence,
            )
        return (
            ChecklistItemStatus.PASS,
            "Rogue DHCP detection is active on every interface serving DHCP.",
            evidence,
        )

    async def _check_wireguard(
        self, router: Any, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        # Imported locally, not at module scope, to keep this domain's own
        # module-level import graph free of a hard dependency on
        # wireguard.exceptions -- only this one method needs it.
        from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError

        try:
            peer = await self.wireguard_lookup.get_peer(
                router_id=router.id,
                requesting_organization_id=requesting_organization_id,
            )
        except WireGuardPeerNotFoundError:
            return (
                ChecklistItemStatus.NOT_CHECKED,
                "No WireGuard tunnel is configured for this router.",
                {"configured": False},
            )
        health = self.wireguard_lookup.compute_health_status(peer)
        health_value = getattr(health, "value", str(health))
        evidence = {
            "configured": True,
            "peer_status": peer.status,
            "last_handshake_at": peer.last_handshake_at.isoformat()
            if peer.last_handshake_at
            else None,
            "health_status": health_value,
        }
        if health_value == "healthy":
            return (
                ChecklistItemStatus.PASS,
                "WireGuard tunnel has a recent handshake.",
                evidence,
            )
        if health_value == "unknown":
            return (
                ChecklistItemStatus.NOT_CHECKED,
                "WireGuard tunnel has never completed a handshake.",
                evidence,
            )
        return (
            ChecklistItemStatus.FAIL,
            f"WireGuard tunnel is {health_value}.",
            evidence,
        )

    def _check_api_reachability(
        self, router: Any
    ) -> tuple[ChecklistItemStatus, str, dict[str, Any]]:
        health_status = getattr(router, "health_status", None)
        evidence = {"health_status": health_status}
        if health_status == "healthy":
            return (
                ChecklistItemStatus.PASS,
                "Most recent reachability check succeeded.",
                evidence,
            )
        if health_status == "unhealthy":
            return (
                ChecklistItemStatus.FAIL,
                "Most recent reachability check failed.",
                evidence,
            )
        return (
            ChecklistItemStatus.NOT_CHECKED,
            "No reachability check has run for this router yet.",
            evidence,
        )


def _values(statuses: frozenset[ChecklistItemStatus]) -> frozenset[str]:
    return frozenset(s.value for s in statuses)


__all__ = [
    "ReadinessService",
    "RouterLookupProtocol",
    "IspLinkLookupProtocol",
    "WireGuardLookupProtocol",
    "RouterAgentCredentialLookupProtocol",
]

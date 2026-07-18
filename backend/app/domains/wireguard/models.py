"""SQLAlchemy ORM models for the WireGuard domain.

Both tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

Neither model imports ``app.domains.router.models.Router`` -- only FKs its
table name (``"routers.id"``), the same loose-coupling convention
``app.domains.router_agent.models``/``app.domains.router_provisioning.models``
already establish for their own ``router_id`` columns.

Two models:

* :class:`WireGuardServer` -- a platform-operated WireGuard concentrator
  ("hub") that every router-peer tunnels back to.
* :class:`WireGuardPeer` -- one router's tunnel/peer registration against a
  hub: its allocated tunnel IP, its own (platform-generated) keypair, and
  its lifecycle status.

## Why exactly one active hub, but not a hard-coded singleton

The module brief (BE-009 Part 3) asks for "exactly one hub to start" as a
**deliberate simplification**, not because the schema can only ever model
one: :class:`WireGuardServer` carries no ``UNIQUE`` constraint or CHECK
forcing ``is_active`` to be true for at most one row, and nothing in
``service.py`` assumes a single row exists -- ``WireGuardService`` resolves
"the" hub via ``WireGuardRepositoryProtocol.get_active_server``, which is
free to be reinterpreted later (e.g. "the nearest active hub to this
router's region") without a schema migration. Multi-region hub support
(picking a hub per router, load-balancing across hubs, etc.) is explicitly
out of scope for this iteration and left as documented future work -- see
``docs/wireguard/README.md``.

## Why the peer's own private key is stored (encrypted) here at all

In a self-managed WireGuard deployment, a peer generates its own keypair and
only ever hands the hub its *public* key. This platform's "cloud-managed"
model inverts that: **the platform generates both sides' keypairs**,
including the peer's, because a physical MikroTik router behind
carrier-grade NAT cannot always be reached to push a self-service
onboarding flow, and zero-touch provisioning (BE-009 Part 1/2) already
establishes the pattern of the platform deciding a device's configuration
and pushing it down wholesale. That means the peer's private key must be
recoverable by the platform in order to ever hand it to the device -- so it
is Fernet-encrypted via the *exact same* ``app.domains.router.crypto
.encrypt_secret``/``decrypt_secret`` helpers BE-008 already established for
``Router.api_credentials_encrypted`` (and Module 009 Part 1 reuses again for
``ConfigVariable.value`` when ``is_secret``), never a second encryption
mechanism. See ``service.py``'s module docstring for the full reasoning.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_WIREGUARD_PORT, PeerStatus


class WireGuardServer(BaseModel):
    """A platform-operated WireGuard concentrator ("hub"). Routers never
    talk to each other directly -- every :class:`WireGuardPeer` tunnels back
    to exactly one hub, identified by ``server_id``.

    ``private_key_encrypted`` is the hub's own private key. It never leaves
    the platform (unlike a peer's private key, which is deliberately
    delivered to the device -- see module docstring), but is still stored
    Fernet-encrypted at rest rather than in the clear, for the same
    defense-in-depth reason BE-008 encrypts RouterOS API credentials it
    otherwise controls entirely server-side: a database compromise should
    not also hand over live cryptographic key material.
    """

    __tablename__ = "wireguard_servers"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    # Public hostname or IP address a router dials to reach this hub -- not
    # necessarily the same as any RouterOS device's own
    # ``management_ip_address``/``public_ip_address`` (BE-008), which
    # describe the *router's* reachability, not the hub's.
    endpoint_host: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint_port: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_WIREGUARD_PORT, nullable=False
    )
    public_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    private_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # The address space tunnel IPs are allocated from for peers of this hub,
    # e.g. "10.100.0.0/16" -- see ``validators.allocate_tunnel_ip``.
    tunnel_network_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_wireguard_servers_is_active", "is_active"),
        Index("ix_wireguard_servers_public_key", "public_key", unique=True),
    )

    def __repr__(self) -> str:
        return (
            f"<WireGuardServer(id={self.id}, name={self.name}, "
            f"active={self.is_active})>"
        )


class WireGuardPeer(BaseModel):
    """One router's WireGuard tunnel/peer registration.

    ``router_id`` is unique -- a router has at most **one** peer row, ever,
    ``one-to-one`` with the ``routers`` table (see module docstring). This
    deliberately mirrors ``app.domains.router_agent.models
    .RouterAgentCredential.router_id``'s own unique-FK-plus-in-place-rotation
    design rather than ``app.domains.router_provisioning.models
    .ConfigVersion``'s append-only-history design: unlike a config version
    (where every past rendered config is independently meaningful audit
    trail), a router's *previous* WireGuard keypair/tunnel IP has no
    standalone value once superseded -- it is dead key material pointing at
    an address no longer routed to that peer. ``rotation_count`` plus the
    ``TunnelRotated``/``TunnelRevoked`` domain events (``events.py``) and the
    ``audit_log_entries`` row every mutation writes are what preserve *that
    a* rotation/revocation happened and when, without a second table
    duplicating three columns (router, actor, timestamp) already captured
    twice over -- the identical "don't add a table for data already
    captured" discipline ``app.domains.router_provisioning.models``'s module
    docstring documents for why it has no ``RouterSecretRotationLog``.

    ``tunnel_ip_address`` is unique **per hub** (``server_id`` +
    ``tunnel_ip_address``), not globally -- two different hubs could
    plausibly (if a future multi-hub design allocates overlapping CIDRs)
    assign the same literal address to two different peers without
    conflict, since it is only ever routed to the peer through that specific
    hub's own tunnel interface.
    """

    __tablename__ = "wireguard_peers"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("wireguard_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tunnel_ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The peer's own private key -- generated by the platform, delivered to
    # the device once it authenticates via its existing
    # ``app.domains.router_agent`` credential. See module docstring for why
    # this is stored (encrypted) at all.
    private_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=PeerStatus.PENDING.value, nullable=False
    )
    # Incremented every time this peer's keypair is rotated (see
    # ``service.py``'s ``rotate_tunnel``) -- mirrors
    # ``RouterAgentCredential.rotation_count``'s identical bookkeeping.
    rotation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Device-reported liveness signal (see ``constants.HealthStatus`` /
    # ``WireGuardService.compute_health_status``). ``None`` until the first
    # handshake is ever reported -- meaning "unknown", the identical
    # "None means unknown, not its own enum value" posture
    # ``Router.health_status`` already establishes.
    last_handshake_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("router_id", name="uq_wireguard_peers_router_id"),
        UniqueConstraint("public_key", name="uq_wireguard_peers_public_key"),
        UniqueConstraint(
            "server_id",
            "tunnel_ip_address",
            name="uq_wireguard_peers_server_id_tunnel_ip_address",
        ),
        Index("ix_wireguard_peers_router_id", "router_id", unique=True),
        Index("ix_wireguard_peers_server_id", "server_id"),
        Index("ix_wireguard_peers_status", "status"),
        Index("ix_wireguard_peers_tunnel_ip_address", "tunnel_ip_address"),
    )

    def is_revoked(self) -> bool:
        return self.status == PeerStatus.REVOKED.value

    def __repr__(self) -> str:
        return (
            f"<WireGuardPeer(router_id={self.router_id}, "
            f"tunnel_ip_address={self.tunnel_ip_address}, status={self.status})>"
        )


__all__ = ["WireGuardServer", "WireGuardPeer"]

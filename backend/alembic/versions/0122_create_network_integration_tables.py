"""``network_integrations``, ``network_integration_events`` and
``network_integration_authorizations`` -- the schema behind a tenant
connecting their own third-party network controller (TP-Link Omada is the
first, and the only, provider) to this platform.

See ``app.domains.network_integration.models`` for the full design
write-up. What follows is the part that belongs at the schema level: why
this is three tables, why ``organization_id`` is on all three, what the
partial unique index does and does not promise, why one foreign key is
``SET NULL`` where its neighbours are ``CASCADE``, and why there is
nothing to backfill.

## Three tables, not one

They hold three different kinds of fact, and folding them together would
destroy the distinction rather than simplify it.

``network_integrations`` is **current state**: one row per (tenant,
controller, site), and the row's own columns *are* the truth about that
integration right now. It is read on every list view and on every portal
authorization, and it is updated in place.

``network_integration_events`` is an **append-only operational feed** --
why the current state is what it is. It exists next to
``audit_log_entries`` rather than inside it because most of what happens
to an integration is not caused by a human: a background sync failing at
03:00 has no ``actor_user_id`` to record, and a venue owner debugging "why
did guest WiFi stop last night" should not be handed their organization's
entire RBAC audit trail to search. Human-caused actions here still write a
real ``audit_log_entries`` row through the existing audit domain; there is
no second audit table.

``network_integration_authorizations`` is an **append-only record of what
this platform asked a controller to do** for one guest. Its rows are
per-guest-join and will vastly outnumber the other two tables; keeping
them out of the event feed keeps "show me this integration's last twenty
events" from paging through a week of guest joins.

A single ``network_integration_log`` table with a discriminator column
would have to be nullable in almost every column, and every query against
it would carry a ``WHERE kind = ...`` that a future reader can forget.

## ``organization_id`` on all three, including where it is derivable

``network_integration_events.organization_id`` and
``network_integration_authorizations.organization_id`` are both reachable
by joining back to ``network_integrations``. They are stored anyway, for
the same reason ``guest_sessions.organization_id`` is: every read of these
tables is tenant-scoped, and the denormalized column makes that filter an
indexed equality instead of a join.

The sharper reason is that the tenant filter here is a *security* control,
not an optimization. A security control that depends on a join is one a
future query can silently omit while still returning rows -- it still
compiles, it still returns data, and the data is another tenant's. An
``organization_id`` column on the row being read keeps the filter local to
the query that needs it. This codebase has produced a real cross-tenant
read before (see the path-id scoping defect class), which is why this is
written down rather than assumed.

Both copies are immutable after insert. Nothing in the domain updates
them.

## The partial unique index, and why NULL sites deliberately do not conflict

``uq_network_integrations_org_provider_base_url_site`` covers
``(organization_id, provider, base_url, external_site_id)`` and carries
``postgresql_where = is_deleted = false``.

Partial, because all three tables extend ``BaseModel`` and are therefore
soft-deleted. A plain unique index would mean a venue that deletes an
integration can never re-add the same controller and site again -- the
tombstone would keep occupying the slot forever. Partial on
``is_deleted = false`` gives the honest rule: within one organization, one
provider may have at most one *live* row per (controller URL, site), and a
re-add creates a fresh row while the old one stays readable for its audit
trail.

Postgres treats every NULL as distinct in a unique index, so two rows with
``external_site_id IS NULL`` do not conflict. That is deliberate, not an
oversight to be patched with a ``COALESCE``: a row with no site selected
yet is a half-finished connect wizard, and two half-finished wizards
against the same controller are not yet duplicates of anything. Refusing
the second would break the wizard for the operator who opened it twice.
The cost is that the index cannot enforce "one unconfigured draft per
controller" -- accepted, because that is not a rule worth having.

## ``guest_session_id`` is ``ON DELETE SET NULL``, not CASCADE

Every other FK on ``network_integration_authorizations`` that points at a
row the authorization cannot exist without (``integration_id``,
``organization_id``) is ``CASCADE``. ``guest_session_id`` is not, and the
difference is the point: a guest session being purged -- retention, a GDPR
erasure -- must not delete the record that this platform reached into a
customer's network controller and authorized a device. The action
happened. Cascading would make the platform's own record of its own
outbound action disappear because the *subject* of that action was
erased, which is exactly backwards for an audit-shaped table.

``location_id`` is ``SET NULL`` for the same reason on a smaller scale: a
deleted location must not take the history of what happened at it along.

## Native enums are not used anywhere here

``provider``, ``status``, ``auth_mode``, ``last_sync_status``,
``event_type`` and the authorization ``status`` are all plain
``VARCHAR`` -- the same "no native enum" posture every other status column
in this codebase takes, so adding a provider or an eighth status is a code
change and not an ``ALTER TYPE`` migration. The ``server_default``s below
are the literal enum values from
``app.domains.network_integration.constants``, spelled out rather than
imported: a migration is a frozen snapshot of the schema at its own point
in history, and importing a live constant would let a future rename
rewrite what this migration did.

## Nothing to backfill, and the feature is inert until a row exists

Three new tables with no pre-existing rows, so there is no honest state to
backfill *to*. Absence is already the correct answer: with no
``network_integrations`` row, no sync sweep selects anything, no portal
authorize call resolves an integration, and every existing customer keeps
working exactly as before with no Omada anywhere in the picture. Seeding a
row in any state would be asserting that a tenant has connected a
controller nobody has connected.

The reverse also holds and is worth stating plainly: nothing in this
migration has been exercised against a real Omada controller. It creates
tables; whether the provider layer above them works against real hardware
is not something this file can or does claim.

Revision ID: 0122_create_network_integration_tables
Revises: 0113_create_router_rogue_dhcp_statuses_table
Create Date: 2026-09-10
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0122_create_network_integration_tables"
down_revision = "0121_add_quotation_payment_and_terms"
branch_labels = None
depends_on = None

INTEGRATIONS = "network_integrations"
EVENTS = "network_integration_events"
AUTHORIZATIONS = "network_integration_authorizations"


# ``_base_model_columns``/``_create_base_model_indexes``/
# ``_drop_base_model_indexes`` are duplicated verbatim into each migration
# that needs them rather than imported from a shared module -- the
# convention this directory has followed since ``0012_create_otp_tables``,
# so a migration stays a frozen snapshot of the schema at its own point in
# history and cannot be changed retroactively by editing a helper.
def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def _upgrade_integrations() -> None:
    op.create_table(
        INTEGRATIONS,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Nullable: a controller may serve several of the tenant's venues,
        # or be registered before the operator maps it to a WyfyGuest
        # location. The portal authorize path resolves an integration *by
        # location*, so a NULL here means the row is never selected for a
        # portal authorization -- honest, rather than guessing at a
        # mapping nobody made. SET NULL, not CASCADE: deleting a location
        # must not delete the tenant's controller registration.
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # The fleet-inventory row representing this controller, when one
        # exists -- contract §11.3. See NetworkIntegration.router_id's own
        # comment for why an Omada controller gets a `Router` row at all
        # (short version: `guest_sessions.router_id` is NOT NULL, so an
        # Omada-only venue could not create a guest session without one).
        #
        # Nullable, and it must stay nullable: a customer self-service
        # integration has no fleet row, only the Master-driven onboarding
        # path creates the pair. SET NULL rather than CASCADE -- retiring
        # the fleet device must not silently delete the tenant's
        # controller registration along with its credentials and its
        # authorization history.
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Plain VARCHAR, and the default is the literal enum value rather
        # than an import -- see the module docstring's "native enums are
        # not used anywhere here".
        sa.Column(
            "provider", sa.String(length=30), nullable=False, server_default="omada"
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default="unconfigured",
        ),
        # Intention and observation, kept apart. ``is_enabled`` is what the
        # operator asked for; ``status`` is what was observed. One column
        # would make "disabled" and "broken" the same value, and then
        # re-enabling an integration would have nothing to restore it to.
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        # Normalized by validators.validate_controller_url before any row
        # is written: lowercase scheme+host, explicit port, no path. Safe
        # to show a customer -- it is what they typed. 512 rather than 255
        # because it is a user-supplied URL and truncating one silently
        # would produce an integration that points somewhere else.
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column(
            "auth_mode", sa.String(length=20), nullable=False, server_default="openapi"
        ),
        # The controller's own ``omadacId``, discovered on the first
        # successful connection rather than typed in -- hence nullable.
        sa.Column("controller_id", sa.String(length=128), nullable=True),
        sa.Column("controller_version", sa.String(length=64), nullable=True),
        sa.Column("external_site_id", sa.String(length=128), nullable=True),
        # Cached beside the id so a list view can render a site name
        # without a live controller call per row. May be stale between
        # syncs; only the *id* is ever sent to the controller, so a stale
        # name is cosmetic.
        sa.Column("external_site_name", sa.String(length=255), nullable=True),
        sa.Column("guest_ssid_id", sa.String(length=128), nullable=True),
        sa.Column("guest_ssid_name", sa.String(length=255), nullable=True),
        # Fernet ciphertext of a JSON credential set, encrypted with
        # ``Settings.network_integration_encryption_key`` (a separate key
        # from ``router_encryption_key`` -- see
        # app.domains.network_integration.crypto). One Text column rather
        # than four nullable encrypted ones. Never returned by any
        # endpoint, never logged; the API exposes ``has_credentials: bool``
        # and nothing else. Nullable because a row exists before
        # credentials are entered.
        sa.Column("credentials_encrypted", sa.Text(), nullable=True),
        sa.Column(
            "session_duration_seconds",
            sa.Integer(),
            nullable=False,
            server_default="3600",
        ),
        sa.Column(
            "sync_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default="300",
        ),
        # Provider-shaped extras that do not deserve a column each: cached
        # device/client counts from the last sync, the consecutive-failure
        # counter the sync backoff reads. Deliberately not a home for
        # anything a query has to filter on -- those get real columns.
        sa.Column(
            "provider_metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        # "never" is a real third value, not a NULL. "has never been
        # polled" and "was polled and it went fine" are different facts,
        # and a dashboard rendering a blank for the first invites the
        # reader to assume the second.
        sa.Column(
            "last_sync_status",
            sa.String(length=20),
            nullable=False,
            server_default="never",
        ),
        # The most recent failure, denormalized onto the row so a list view
        # can show "why is this red" without reading the events table once
        # per row. The events table stays the full history.
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_base_model_indexes(INTEGRATIONS)
    op.create_index(
        f"ix_{INTEGRATIONS}_organization_id", INTEGRATIONS, ["organization_id"]
    )
    op.create_index(f"ix_{INTEGRATIONS}_location_id", INTEGRATIONS, ["location_id"])
    # Looked up in the reverse direction too: given a fleet device, the
    # Master console asks "is there an integration behind this row?" when
    # rendering an Omada controller's detail view.
    op.create_index(f"ix_{INTEGRATIONS}_router_id", INTEGRATIONS, ["router_id"])
    # The platform (Master console) list filters on provider and status
    # together; the composite is what that query uses.
    op.create_index(
        f"ix_{INTEGRATIONS}_provider_status", INTEGRATIONS, ["provider", "status"]
    )
    # The sync sweep's own selection predicate starts here.
    op.create_index(f"ix_{INTEGRATIONS}_is_enabled", INTEGRATIONS, ["is_enabled"])
    # Partial on ``is_deleted = false``, and NULL ``external_site_id``
    # deliberately does not conflict -- see the module docstring.
    op.create_index(
        f"uq_{INTEGRATIONS}_org_provider_base_url_site",
        INTEGRATIONS,
        ["organization_id", "provider", "base_url", "external_site_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )


def _upgrade_events() -> None:
    op.create_table(
        EVENTS,
        *_base_model_columns(),
        # CASCADE: an event is meaningless without the integration it
        # describes, and the integration is soft-deleted in normal
        # operation anyway -- this fires only on a real hard delete.
        sa.Column(
            "integration_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("network_integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Denormalized tenant filter -- see the module docstring for why
        # this is stored rather than joined.
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        # ``message`` and ``context`` are pre-redacted at *write* time by
        # service.py (see constants.REDACTED_CONTEXT_KEYS) rather than by a
        # log filter. These two columns are rendered straight into the
        # customer dashboard, so a secret that reaches them has already
        # left the building by the time any log filter would see it.
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "context",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    _create_base_model_indexes(EVENTS)
    op.create_index(f"ix_{EVENTS}_integration_id", EVENTS, ["integration_id"])
    op.create_index(f"ix_{EVENTS}_organization_id", EVENTS, ["organization_id"])
    op.create_index(f"ix_{EVENTS}_event_type", EVENTS, ["event_type"])
    # ``created_at`` alone is already indexed by the BaseModel columns
    # above. This composite is what the feed query actually uses -- one
    # integration's events, newest first -- and it is the difference
    # between an index scan and a sort over every event the tenant has
    # ever produced.
    op.create_index(
        f"ix_{EVENTS}_integration_created", EVENTS, ["integration_id", "created_at"]
    )


def _upgrade_authorizations() -> None:
    op.create_table(
        AUTHORIZATIONS,
        *_base_model_columns(),
        sa.Column(
            "integration_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("network_integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # SET NULL, not CASCADE, and the difference is deliberate: a guest
        # session being purged (retention, a GDPR erasure) must not delete
        # this platform's own record that it reached into a customer's
        # controller. The row survives with a null session reference --
        # the action happened, the subject's record did not. See the
        # module docstring.
        sa.Column(
            "guest_session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guest_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Canonical uppercase colon-separated form (17 chars), normalized
        # by validators.normalize_client_mac before the row is written.
        sa.Column("client_mac", sa.String(length=17), nullable=False),
        sa.Column("ap_mac", sa.String(length=17), nullable=True),
        sa.Column("ssid_name", sa.String(length=255), nullable=True),
        sa.Column("external_site_id", sa.String(length=128), nullable=True),
        # What this platform asked for and what the controller said at that
        # moment -- not a mirror of live controller state. The controller
        # can expire or revoke an authorization with no notification (there
        # is no webhook for it in Omada's controller API), so
        # ``authorized`` with a future ``expires_at`` means "we asked, and
        # it was accepted", never "this device is online right now".
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="authorized",
        ),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deauthorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
    )
    _create_base_model_indexes(AUTHORIZATIONS)
    # "How many live authorizations does this integration have" -- the
    # count the status endpoint and the platform summary both render.
    op.create_index(
        f"ix_{AUTHORIZATIONS}_integration_status",
        AUTHORIZATIONS,
        ["integration_id", "status"],
    )
    # The tenant-scoped, time-ordered read: one organization's
    # authorizations, newest first.
    op.create_index(
        f"ix_{AUTHORIZATIONS}_org_authorized_at",
        AUTHORIZATIONS,
        ["organization_id", "authorized_at"],
    )
    # Support's actual question: "did this device get authorized, and
    # when". Not unique -- one MAC authorizes once per join, so repeats
    # are expected and are the history.
    op.create_index(f"ix_{AUTHORIZATIONS}_client_mac", AUTHORIZATIONS, ["client_mac"])
    op.create_index(f"ix_{AUTHORIZATIONS}_location_id", AUTHORIZATIONS, ["location_id"])
    op.create_index(
        f"ix_{AUTHORIZATIONS}_guest_session_id", AUTHORIZATIONS, ["guest_session_id"]
    )


def upgrade() -> None:
    # ``network_integrations`` first: the other two carry foreign keys into
    # it.
    _upgrade_integrations()
    _upgrade_events()
    _upgrade_authorizations()


def downgrade() -> None:
    # Reverse dependency order -- the two child tables reference
    # ``network_integrations``, so they go first. Indexes are dropped
    # explicitly before each table rather than relying on the implicit
    # drop, matching every other migration in this directory.
    op.drop_index(f"ix_{AUTHORIZATIONS}_guest_session_id", table_name=AUTHORIZATIONS)
    op.drop_index(f"ix_{AUTHORIZATIONS}_location_id", table_name=AUTHORIZATIONS)
    op.drop_index(f"ix_{AUTHORIZATIONS}_client_mac", table_name=AUTHORIZATIONS)
    op.drop_index(f"ix_{AUTHORIZATIONS}_org_authorized_at", table_name=AUTHORIZATIONS)
    op.drop_index(f"ix_{AUTHORIZATIONS}_integration_status", table_name=AUTHORIZATIONS)
    _drop_base_model_indexes(AUTHORIZATIONS)
    op.drop_table(AUTHORIZATIONS)

    op.drop_index(f"ix_{EVENTS}_integration_created", table_name=EVENTS)
    op.drop_index(f"ix_{EVENTS}_event_type", table_name=EVENTS)
    op.drop_index(f"ix_{EVENTS}_organization_id", table_name=EVENTS)
    op.drop_index(f"ix_{EVENTS}_integration_id", table_name=EVENTS)
    _drop_base_model_indexes(EVENTS)
    op.drop_table(EVENTS)

    op.drop_index(
        f"uq_{INTEGRATIONS}_org_provider_base_url_site", table_name=INTEGRATIONS
    )
    op.drop_index(f"ix_{INTEGRATIONS}_is_enabled", table_name=INTEGRATIONS)
    op.drop_index(f"ix_{INTEGRATIONS}_provider_status", table_name=INTEGRATIONS)
    op.drop_index(f"ix_{INTEGRATIONS}_router_id", table_name=INTEGRATIONS)
    op.drop_index(f"ix_{INTEGRATIONS}_location_id", table_name=INTEGRATIONS)
    op.drop_index(f"ix_{INTEGRATIONS}_organization_id", table_name=INTEGRATIONS)
    _drop_base_model_indexes(INTEGRATIONS)
    op.drop_table(INTEGRATIONS)

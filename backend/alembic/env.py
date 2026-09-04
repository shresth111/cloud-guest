from logging.config import fileConfig

from sqlalchemy import Connection, engine_from_config, inspect, pool, text

from alembic import context
from app.core.config import get_settings
from app.database.base import Base

# Import domain models so their tables are registered on Base.metadata
# before autogenerate compares it against the database.
# Every domain that defines ORM models must be imported here, not just the
# ones a past migration happened to need.
#
# `target_metadata` below is `Base.metadata`, and a model class only lands in
# it when its module is imported. Nineteen domains -- vlan, dhcp, qos,
# port_forwarding, content_filtering, hotspot, isp, campaigns,
# channel_partner, support_tickets, quotation and others -- were missing, so
# Alembic could not see **30 tables** that exist in the database.
#
# Nothing had gone wrong yet only because every migration in this directory
# is hand-written. The first person to run `alembic revision --autogenerate`
# would have been handed a migration that DROPS all thirty, including
# `vlans`, `dhcp_pools`, `channel_partners`, `campaigns`, `support_tickets`
# and `quotations` -- because autogenerate reads "in the database, not in the
# metadata" as "this table was deleted".
#
# `tests/unit/test_migrations.py` asserts this list stays complete, so the
# next domain to define models cannot quietly reopen it.
from app.domains.analytics import models as analytics_models  # noqa: F401
from app.domains.api_keys import models as api_keys_models  # noqa: F401
from app.domains.assistant import models as assistant_models  # noqa: F401
from app.domains.auth import models as auth_models  # noqa: F401
from app.domains.billing import models as billing_models  # noqa: F401
from app.domains.branding import models as branding_models  # noqa: F401
from app.domains.campaigns import models as campaigns_models  # noqa: F401
from app.domains.captive_portal import models as captive_portal_models  # noqa: F401
from app.domains.channel_partner import models as channel_partner_models  # noqa: F401
from app.domains.connected_devices import (
    models as connected_devices_models,  # noqa: F401,E501
)
from app.domains.content_filtering import (
    models as content_filtering_models,  # noqa: F401,E501
)

# demo_request is imported alongside demo_booking, not for its own sake:
# DemoBooking.demo_request_id is a ForeignKey("demo_requests.id"), and
# SQLAlchemy resolves that target by table name at mapper-configuration
# time -- with only one of the pair registered, Base.metadata would hold a
# dangling reference. (demo_requests was previously absent from this list
# entirely, along with several other domains -- a pre-existing gap in
# autogenerate coverage, not something this migration introduced.)
from app.domains.demo_booking import models as demo_booking_models  # noqa: F401
from app.domains.demo_request import models as demo_request_models  # noqa: F401
from app.domains.device_sync import models as device_sync_models  # noqa: F401
from app.domains.dhcp import models as dhcp_models  # noqa: F401
from app.domains.dns import models as dns_models  # noqa: F401
from app.domains.firewall import models as firewall_models  # noqa: F401
from app.domains.guest import models as guest_models  # noqa: F401
from app.domains.guest_access import models as guest_access_models  # noqa: F401
from app.domains.guest_teams import models as guest_teams_models  # noqa: F401
from app.domains.hotspot import models as hotspot_models  # noqa: F401
from app.domains.isp import models as isp_models  # noqa: F401
from app.domains.isp_routing import models as isp_routing_models  # noqa: F401
from app.domains.location import models as location_models  # noqa: F401
from app.domains.mac_authorization import (
    models as mac_authorization_models,  # noqa: F401,E501
)
from app.domains.monitored_hardware import (
    models as monitored_hardware_models,  # noqa: F401
)
from app.domains.monitoring import models as monitoring_models  # noqa: F401
from app.domains.network_device import models as network_device_models  # noqa: F401
from app.domains.network_diagnostics import (
    models as network_diagnostics_models,  # noqa: F401,E501
)
from app.domains.notification import models as notification_models  # noqa: F401
from app.domains.organization import models as organization_models  # noqa: F401
from app.domains.otp import models as otp_models  # noqa: F401
from app.domains.policy import models as policy_models  # noqa: F401
from app.domains.port_forwarding import models as port_forwarding_models  # noqa: F401
from app.domains.provisioning_engine import (
    models as provisioning_engine_models,  # noqa: F401,E501
)
from app.domains.qos import models as qos_models  # noqa: F401
from app.domains.queue_management import models as queue_management_models  # noqa: F401
from app.domains.quotation import models as quotation_models  # noqa: F401
from app.domains.rbac import models as rbac_models  # noqa: F401
from app.domains.readiness import models as readiness_models  # noqa: F401
from app.domains.router import models as router_models  # noqa: F401
from app.domains.router_agent import models as router_agent_models  # noqa: F401
from app.domains.router_provisioning import (
    models as router_provisioning_models,  # noqa: F401,E501
)
from app.domains.support_tickets import models as support_tickets_models  # noqa: F401
from app.domains.system_settings import models as system_settings_models  # noqa: F401
from app.domains.vlan import models as vlan_models  # noqa: F401
from app.domains.voucher import models as voucher_models  # noqa: F401
from app.domains.wireguard import models as wireguard_models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", str(settings.database_url))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=str(settings.database_url).replace("+asyncpg", ""),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# This project's revision ids are long, descriptive slugs (e.g.
# ``0004_add_organization_fk_to_rbac_tables`` -- 39 chars), but the
# ``alembic_version.version_num`` column Alembic auto-creates on a brand-new
# database is ``VARCHAR(32)`` (and the installed Alembic, 1.14.0, exposes no
# ``context.configure()`` knob to widen it -- only the third-party-dialect
# ``version_table_impl`` hook). On a fresh database ``upgrade head``
# therefore dies with ``StringDataRightTruncation`` the moment revision 0004
# is stamped, and the whole single-transaction run rolls back to an empty
# schema. Long-lived environments were widened by hand long ago, so
# this bites exactly the from-scratch bootstraps (CI, new dev machines, DR
# restores) that have no human around to widen it.
_VERSION_TABLE = "alembic_version"
_VERSION_NUM_WIDTH = 255


def _prepare_version_table(connection: Connection) -> None:
    """Make ``alembic_version.version_num`` wide enough *before* Alembic
    touches it: pre-create the table with a wide column on a fresh database
    (Alembic's own creation is ``checkfirst=True``, so it then leaves ours
    alone), and widen it in place on a database still carrying the old
    ``VARCHAR(32)`` shape. Databases already widened (every long-lived
    environment) match neither condition and are untouched.

    PostgreSQL-only by design: SQLite and friends don't enforce VARCHAR
    lengths, so there is nothing to fix elsewhere. Runs on its own
    short-lived connection, committed before the migration transaction
    opens; a leftover empty ``alembic_version`` table from a later-failed
    run is indistinguishable from no table as far as Alembic is concerned.
    """
    if connection.dialect.name != "postgresql":
        return
    inspector = inspect(connection)
    if not inspector.has_table(_VERSION_TABLE):
        connection.execute(
            text(
                f"CREATE TABLE {_VERSION_TABLE} ("
                f"version_num VARCHAR({_VERSION_NUM_WIDTH}) NOT NULL, "
                f"CONSTRAINT {_VERSION_TABLE}_pkc PRIMARY KEY (version_num))"
            )
        )
        return
    version_num = next(
        (
            column
            for column in inspector.get_columns(_VERSION_TABLE)
            if column["name"] == "version_num"
        ),
        None,
    )
    length = getattr(version_num["type"], "length", None) if version_num else None
    if length is not None and length < _VERSION_NUM_WIDTH:
        connection.execute(
            text(
                f"ALTER TABLE {_VERSION_TABLE} ALTER COLUMN version_num "
                f"TYPE VARCHAR({_VERSION_NUM_WIDTH})"
            )
        )


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    url = str(settings.database_url).replace("+asyncpg", "")
    configuration["sqlalchemy.url"] = url
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        _prepare_version_table(connection)
        connection.commit()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

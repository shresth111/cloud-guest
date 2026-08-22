from logging.config import fileConfig

from sqlalchemy import Connection, engine_from_config, inspect, pool, text

from alembic import context
from app.core.config import get_settings
from app.database.base import Base

# Import domain models so their tables are registered on Base.metadata
# before autogenerate compares it against the database.
from app.domains.analytics import models as analytics_models  # noqa: F401
from app.domains.api_keys import models as api_keys_models  # noqa: F401
from app.domains.auth import models as auth_models  # noqa: F401
from app.domains.billing import models as billing_models  # noqa: F401
from app.domains.captive_portal import models as captive_portal_models  # noqa: F401

# demo_request is imported alongside demo_booking, not for its own sake:
# DemoBooking.demo_request_id is a ForeignKey("demo_requests.id"), and
# SQLAlchemy resolves that target by table name at mapper-configuration
# time -- with only one of the pair registered, Base.metadata would hold a
# dangling reference. (demo_requests was previously absent from this list
# entirely, along with several other domains -- a pre-existing gap in
# autogenerate coverage, not something this migration introduced.)
from app.domains.demo_booking import models as demo_booking_models  # noqa: F401
from app.domains.demo_request import models as demo_request_models  # noqa: F401
from app.domains.dns import models as dns_models  # noqa: F401
from app.domains.firewall import models as firewall_models  # noqa: F401
from app.domains.guest import models as guest_models  # noqa: F401
from app.domains.guest_access import models as guest_access_models  # noqa: F401
from app.domains.guest_teams import models as guest_teams_models  # noqa: F401
from app.domains.location import models as location_models  # noqa: F401
from app.domains.monitored_hardware import (
    models as monitored_hardware_models,  # noqa: F401
)
from app.domains.monitoring import models as monitoring_models  # noqa: F401
from app.domains.network_device import models as network_device_models  # noqa: F401
from app.domains.notification import models as notification_models  # noqa: F401
from app.domains.organization import models as organization_models  # noqa: F401
from app.domains.otp import models as otp_models  # noqa: F401
from app.domains.policy import models as policy_models  # noqa: F401
from app.domains.provisioning_engine import (
    models as provisioning_engine_models,  # noqa: F401,E501
)
from app.domains.rbac import models as rbac_models  # noqa: F401
from app.domains.readiness import models as readiness_models  # noqa: F401
from app.domains.router import models as router_models  # noqa: F401
from app.domains.router_agent import models as router_agent_models  # noqa: F401
from app.domains.router_provisioning import (
    models as router_provisioning_models,  # noqa: F401,E501
)
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

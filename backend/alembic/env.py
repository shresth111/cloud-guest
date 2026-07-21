from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

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
from app.domains.dns import models as dns_models  # noqa: F401
from app.domains.firewall import models as firewall_models  # noqa: F401
from app.domains.guest import models as guest_models  # noqa: F401
from app.domains.guest_access import models as guest_access_models  # noqa: F401
from app.domains.guest_teams import models as guest_teams_models  # noqa: F401
from app.domains.location import models as location_models  # noqa: F401
from app.domains.monitoring import models as monitoring_models  # noqa: F401
from app.domains.network_device import models as network_device_models  # noqa: F401
from app.domains.notification import models as notification_models  # noqa: F401
from app.domains.organization import models as organization_models  # noqa: F401
from app.domains.otp import models as otp_models  # noqa: F401
from app.domains.policy import models as policy_models  # noqa: F401
from app.domains.rbac import models as rbac_models  # noqa: F401
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

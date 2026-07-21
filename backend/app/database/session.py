from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings


def create_engine(settings: Settings | None = None) -> AsyncEngine:
    app_settings = settings or get_settings()
    return create_async_engine(
        str(app_settings.database_url),
        pool_size=app_settings.database_pool_size,
        max_overflow=app_settings.database_max_overflow,
        pool_timeout=app_settings.database_pool_timeout,
        pool_pre_ping=True,
    )


engine = create_engine()
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


from redis.asyncio import Redis

from app.core.config import Settings, get_settings


def create_redis_client(settings: Settings | None = None) -> Redis:
    app_settings = settings or get_settings()
    return Redis.from_url(
        str(app_settings.redis_url),
        encoding="utf-8",
        decode_responses=True,
        socket_timeout=app_settings.redis_health_timeout_seconds,
        socket_connect_timeout=app_settings.redis_health_timeout_seconds,
    )


redis_client = create_redis_client()


async def get_redis_client() -> Redis:
    return redis_client


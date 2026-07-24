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


def create_pubsub_redis_client(settings: Settings | None = None) -> Redis:
    """A second, dedicated Redis client for long-lived Pub/Sub
    subscriptions (a WebSocket relay's ``pubsub.listen()`` loop -- see
    e.g. ``app.domains.support_tickets.router._run_live_relay``), with
    **no** read-socket timeout.

    ``redis_client`` above sets ``socket_timeout`` to
    ``Settings.redis_health_timeout_seconds`` (2s by default) -- correct
    for the fast-fail request/response calls (``PUBLISH``, health pings)
    every other caller of ``get_redis_client`` makes, but fatal for
    ``pubsub.listen()``: that call blocks on the *same* socket waiting for
    the next published message, which -- unlike a command's response --
    has no bound on how long it may legitimately take to arrive (a support
    ticket may go minutes or hours between replies). Sharing
    ``redis_client``'s short ``socket_timeout`` makes every idle Pub/Sub
    connection die with a raw ``TimeoutError`` after ~2s of silence
    (confirmed with a direct reproduction against
    ``redis_client.pubsub()`` while building the real-time reply feature --
    not a theoretical concern), which a WebSocket relay's own exception
    handling then surfaces as an abrupt client-side disconnect. This client
    keeps the short ``socket_connect_timeout`` (establishing the TCP
    connection itself should still fail fast) but sets
    ``socket_timeout=None`` -- "block indefinitely waiting for the next
    message" is exactly the behavior a long-lived Pub/Sub subscriber needs.
    """
    app_settings = settings or get_settings()
    return Redis.from_url(
        str(app_settings.redis_url),
        encoding="utf-8",
        decode_responses=True,
        socket_timeout=None,
        socket_connect_timeout=app_settings.redis_health_timeout_seconds,
    )


pubsub_redis_client = create_pubsub_redis_client()


async def get_pubsub_redis_client() -> Redis:
    return pubsub_redis_client


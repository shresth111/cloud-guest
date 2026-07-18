from app.core.config import Settings


def test_settings_defaults_are_valid() -> None:
    settings = Settings()

    assert settings.service_name == "cloudguest-backend"
    assert settings.api_v1_prefix == "/api/v1"
    assert str(settings.database_url).startswith("postgresql+asyncpg://")
    assert str(settings.redis_url).startswith("redis://")


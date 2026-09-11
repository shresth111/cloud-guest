from cryptography.fernet import Fernet

from app.core.config import Settings


def test_settings_defaults_are_valid() -> None:
    settings = Settings()

    assert settings.service_name == "cloudguest-backend"
    assert settings.api_v1_prefix == "/api/v1"
    assert str(settings.database_url).startswith("postgresql+asyncpg://")
    assert str(settings.redis_url).startswith("redis://")



class TestSecretsAtPublicDefault:
    ENV_VARS = [
        "CLOUDGUEST_JWT_SECRET_KEY",
        "CLOUDGUEST_ROUTER_ENCRYPTION_KEY",
        "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY",
        "CLOUDGUEST_MFA_ENCRYPTION_KEY",
    ]

    def test_local_reports_nothing(self) -> None:
        assert Settings(environment="local").secrets_at_public_default() == []
        assert Settings(environment=" Local ").is_local_environment

    def test_production_on_defaults_names_every_secret(self) -> None:
        assert (
            Settings(environment="production").secrets_at_public_default()
            == self.ENV_VARS
        )

    def test_an_unknown_environment_counts_as_real(self) -> None:
        assert Settings(environment="staging").secrets_at_public_default() == (
            self.ENV_VARS
        )

    def test_real_values_are_not_reported(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret_key="a-real-secret-that-is-at-least-32-characters",
            router_encryption_key=Fernet.generate_key().decode(),
            network_integration_encryption_key=Fernet.generate_key().decode(),
            mfa_encryption_key=Fernet.generate_key().decode(),
        )
        assert settings.secrets_at_public_default() == []
        assert not settings.uses_public_network_integration_key()

    def test_only_the_unset_key_is_named(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret_key="a-real-secret-that-is-at-least-32-characters",
            router_encryption_key=Fernet.generate_key().decode(),
            mfa_encryption_key=Fernet.generate_key().decode(),
        )
        assert settings.secrets_at_public_default() == [
            "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY"
        ]
        assert settings.uses_public_network_integration_key()

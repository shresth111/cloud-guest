import pytest
from cryptography.fernet import Fernet

from app.core.config import Settings
from app.domains.auth.jwt import JWTError, JWTManager


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


class TestApiDocsExposure:
    def test_docs_enabled_by_default_in_local(self) -> None:
        assert Settings(environment="local").is_docs_enabled is True
        assert Settings(environment="test").is_docs_enabled is True

    def test_docs_disabled_by_default_in_production(self) -> None:
        assert Settings(environment="production").is_docs_enabled is False
        assert Settings(environment="staging").is_docs_enabled is False

    def test_docs_explicit_override(self) -> None:
        assert (
            Settings(environment="production", enable_api_docs=True).is_docs_enabled
            is True
        )
        assert (
            Settings(environment="local", enable_api_docs=False).is_docs_enabled
            is False
        )

    def test_create_app_mounts_docs_in_local(self) -> None:
        from app.main import create_app

        app = create_app(Settings(environment="local"))
        assert app.docs_url == "/docs"
        assert app.redoc_url == "/redoc"
        assert app.openapi_url == "/openapi.json"

    def test_create_app_unmounts_docs_in_production(self) -> None:
        from app.main import create_app

        app = create_app(Settings(environment="production"))
        assert app.docs_url is None
        assert app.redoc_url is None
        assert app.openapi_url is None


class TestStrictProductionSecrets:
    def test_validate_no_public_secrets_noop_in_local(self) -> None:
        Settings(environment="local").validate_no_public_secrets()

    def test_validate_no_public_secrets_raises_in_production_when_defaults_present(
        self,
    ) -> None:
        import pytest

        settings = Settings(environment="production", strict_production_secrets=True)
        with pytest.raises(ValueError, match="Refusing to run in 'production'"):
            settings.validate_no_public_secrets()

    def test_validate_no_public_secrets_succeeds_when_all_configured(self) -> None:
        settings = Settings(
            environment="production",
            strict_production_secrets=True,
            jwt_secret_key="a-real-secret-that-is-at-least-32-characters",
            router_encryption_key=Fernet.generate_key().decode(),
            network_integration_encryption_key=Fernet.generate_key().decode(),
            mfa_encryption_key=Fernet.generate_key().decode(),
        )
        settings.validate_no_public_secrets()

    def test_jwt_encode_refused_under_strict_production_secrets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(environment="production", strict_production_secrets=True)
        assert settings.uses_public_jwt_secret_key()
        monkeypatch.setattr("app.domains.auth.jwt.get_settings", lambda: settings)

        with pytest.raises(JWTError, match="public default JWT secret is forbidden"):
            JWTManager.encode({"sub": "test-user"})



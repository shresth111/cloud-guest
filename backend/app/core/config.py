from functools import lru_cache
from pathlib import Path

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CLOUDGUEST_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(default="local", min_length=2)
    debug: bool = False
    service_name: str = "cloudguest-backend"
    api_v1_prefix: str = "/api/v1"
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )

    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://cloudguest:cloudguest@localhost:5432/cloudguest"
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=120)

    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")
    redis_health_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    jwt_secret_key: str = Field(
        default="insecure-local-dev-secret-key-change-me-32chars",
        min_length=32,
        description=(
            "Secret key used to sign auth JWTs. Must be overridden in every "
            "non-local environment."
        ),
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    max_login_attempts: int = Field(default=5, ge=1, le=100)
    account_lockout_minutes: int = Field(default=30, ge=1, le=1440)
    password_history_limit: int = Field(default=5, ge=0, le=50)

    log_level: str = "INFO"
    log_dir: Path = Path("logs")
    log_file: str = "cloudguest.log"
    log_max_bytes: int = Field(default=10_485_760, ge=1_048_576)
    log_backup_count: int = Field(default=10, ge=1, le=100)

    request_timeout_seconds: int = Field(default=30, ge=1, le=300)

    rbac_permission_cache_ttl_seconds: int = Field(
        default=300,
        ge=1,
        le=86_400,
        description=(
            "TTL for the Redis-backed effective-permission cache "
            "(app.domains.rbac.cache.PermissionCache). Real invalidation "
            "happens on every role/permission/override mutation; this TTL "
            "is only a backstop against a missed invalidation."
        ),
    )
    rbac_max_parent_role_depth: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Maximum number of parent_role_id hops walked when resolving "
            "recursive role-permission inheritance. A defensive backstop "
            "against any cycle that slips past the service-layer check."
        ),
    )

    router_encryption_key: str = Field(
        default="aW5zZWN1cmUtbG9jYWwtZGV2LWZlcm5ldC1rZXkzMiE=",
        min_length=32,
        description=(
            "App-level symmetric key (Fernet, urlsafe-base64) used by "
            "app.domains.router.crypto to encrypt/decrypt RouterOS API "
            "connection credentials at rest. Must be overridden with a real "
            "Fernet key (Fernet.generate_key()) in every non-local "
            "environment -- this is an interim design pending a real "
            "secrets-manager/KMS integration (see "
            "docs/router/ROUTER_ARCHITECTURE.md)."
        ),
    )
    router_provisioning_token_expire_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description=(
            "How long a generated zero-touch-provisioning bearer token "
            "remains valid before a device must have it regenerated."
        ),
    )
    wireguard_handshake_stale_after_minutes: int = Field(
        default=5,
        ge=1,
        le=1440,
        description=(
            "How long since a WireGuard peer's last device-reported "
            "handshake (app.domains.wireguard) before its computed "
            "health status flips from 'healthy' to 'stale'. There is no "
            "live 'wg show' integration in this sandbox -- this is a "
            "DB-tracked, device-reported signal, the same honest interim "
            "posture app.domains.router.models.Router.health_status "
            "already documents. Five minutes is roughly double WireGuard's "
            "own ~2-minute keepalive/handshake-renegotiation cadence, so a "
            "single missed report does not immediately read as unhealthy."
        ),
    )

    otp_code_length: int = Field(
        default=6,
        ge=4,
        le=10,
        description=(
            "Number of digits in a generated OTP code "
            "(app.domains.otp.service.generate_numeric_code)."
        ),
    )
    otp_expiry_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description=(
            "How long a generated OTP code remains valid "
            "(app.domains.otp.models.OtpRequest.expires_at) before "
            "app.domains.otp.exceptions.OtpExpiredError is raised."
        ),
    )
    otp_max_verification_attempts: int = Field(
        default=5,
        ge=1,
        le=20,
        description=(
            "Maximum times a single OTP code may be guessed "
            "(OtpRequest.attempt_count vs. max_attempts) before it locks "
            "itself out (OtpAttemptsExceededError) -- mirrors "
            "max_login_attempts's identical per-secret brute-force cap, "
            "distinct from the request-level throttle below."
        ),
    )
    otp_max_requests_per_window: int = Field(
        default=5,
        ge=1,
        le=100,
        description=(
            "Maximum number of new OTP codes a single identifier "
            "(phone/email) may request within otp_request_window_minutes "
            "(app.domains.otp.service.OtpRateLimiter, Redis-backed) -- "
            "protects the delivery channel from spam, distinct from "
            "otp_max_verification_attempts's per-code brute-force cap."
        ),
    )
    otp_request_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description=(
            "Rolling window (minutes) otp_max_requests_per_window is "
            "measured over -- mirrors account_lockout_minutes's identical "
            "naming/style for a Redis-backed rate window."
        ),
    )

    otel_exporter_otlp_endpoint: str | None = Field(
        default=None,
        description=(
            "OTLP/HTTP collector endpoint (e.g. "
            "'http://localhost:4318/v1/traces') that "
            "app.core.tracing.configure_tracing exports spans to. There is "
            "no real OpenTelemetry Collector/Jaeger/Tempo instance in this "
            "sandbox, so leaving this unset is the honest default: spans "
            "are still generated by a real OpenTelemetry SDK "
            "TracerProvider (app.core.tracing), just exported to the "
            "console (ConsoleSpanExporter) instead of a network collector. "
            "Setting this to a real collector's OTLP/HTTP endpoint in any "
            "non-local environment switches to the real OTLPSpanExporter "
            "with zero code changes."
        ),
    )

    @property
    def log_path(self) -> Path:
        return self.log_dir / self.log_file


@lru_cache
def get_settings() -> Settings:
    return Settings()

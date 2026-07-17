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
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://cloudguest:cloudguest@localhost:5432/cloudguest"
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=120)

    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")
    redis_health_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    log_level: str = "INFO"
    log_dir: Path = Path("logs")
    log_file: str = "cloudguest.log"
    log_max_bytes: int = Field(default=10_485_760, ge=1_048_576)
    log_backup_count: int = Field(default=10, ge=1, le=100)

    request_timeout_seconds: int = Field(default=30, ge=1, le=300)

    @property
    def log_path(self) -> Path:
        return self.log_dir / self.log_file


@lru_cache
def get_settings() -> Settings:
    return Settings()


from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core Application Settings
    ENVIRONMENT: Literal["development", "test", "staging", "production"] = "development"
    APP_NAME: str = "LogicFalcon (powered by AEGIS AI)"
    PRODUCT_NAME: str = "LogicFalcon"
    PLATFORM_NAME: str = "AEGIS AI"
    APP_VERSION: str = "0.1.1"
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False

    # Database Settings
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/aegis",
        description="Async PostgreSQL connection string",
    )
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False

    # Redis Settings
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for caching, rate limiting, and ephemeral state",
    )
    REDIS_POOL_SIZE: int = 10

    # Object Storage (MinIO / S3 compatible)
    OBJECT_STORAGE_ENDPOINT: str = "http://localhost:9000"
    OBJECT_STORAGE_BUCKET: str = "aegis-data"
    OBJECT_STORAGE_ACCESS_KEY: str = "minioadmin"
    OBJECT_STORAGE_SECRET_KEY: str = "minioadmin"
    OBJECT_STORAGE_REGION: str = "us-east-1"
    OBJECT_STORAGE_SECURE: bool = False

    # OpenTelemetry & Observability
    OTEL_ENDPOINT: str = "http://localhost:4317"
    OTEL_ENABLED: bool = False
    OTEL_SERVICE_NAME: str = "aegis-api"

    # Security & Authentication Boundary (External IdP)
    JWT_ISSUER: str = "https://auth.aegis.ai"
    JWT_AUDIENCE: str = "aegis-api"
    DEV_AUTH_ENABLED: bool = True  # Allows header-based or controlled test identity in dev/test

    # Phase 7: Bounded Autonomy & Reliability Engine Settings
    AUTONOMY_ENABLED: bool = True
    AUTONOMY_PRODUCTION_ENABLED: bool = False  # Production default is always False (Level 0/1)
    AUTONOMY_MAX_RISK: str = "LOW"
    AUTONOMY_MAX_TOOL_CALLS: int = 15
    AUTONOMY_MAX_COST_USD: float = 2.0
    AUTONOMY_MAX_DURATION_SECONDS: int = 120
    AUTONOMY_MAX_REMEDIATIONS_PER_INCIDENT: int = 3
    AI_DAILY_BUDGET_USD: float = 50.0

    # Network & CORS Security
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://localhost:8888",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8888",
    ]
    ALLOWED_HOSTS: list[str] = ["localhost", "127.0.0.1", "0.0.0.0", "testserver", "*"]
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10MB limit

    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            import json
            v_str = v.strip()
            if v_str.startswith("[") and v_str.endswith("]"):
                try:
                    parsed: list[str] = json.loads(v_str)
                    return parsed
                except Exception:
                    pass
            return [origin.strip() for origin in v_str.split(",") if origin.strip()]
        if isinstance(v, list):
            return [str(x) for x in v]
        return []

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: Any) -> Any:
        if isinstance(v, str):
            # Render and Supabase frequently provide postgres:// or postgresql://
            if v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql+asyncpg://", 1)
            if v.startswith("postgresql://") and not v.startswith("postgresql+asyncpg://"):
                return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: Any) -> list[str]:
        return cls.parse_cors_origins(v)

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def validate_allowed_hosts(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            import json
            v_str = v.strip()
            if v_str.startswith("[") and v_str.endswith("]"):
                try:
                    parsed: list[str] = json.loads(v_str)
                    return parsed
                except Exception:
                    pass
            return [host.strip() for host in v_str.split(",") if host.strip()]
        if isinstance(v, list):
            return [str(x) for x in v]
        return []


@lru_cache
def get_settings() -> Settings:
    return Settings()

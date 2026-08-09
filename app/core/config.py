from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAPI"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api"

    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_PRIVATE_KEY_B64: str | None = None
    JWT_KID: str = "sentinelapi"
    JWT_ISSUER: str = "SentinelAPI"
    JWT_AUDIENCE: str = "SentinelAPI"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    DATABASE_URL: str
    REDIS_URL: str

    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    BLOCK_THRESHOLD: int = 5
    BLOCK_DURATION: int = 3600

    UPSTREAM_BASE_URL: str = "https://httpbin.org"
    GATEWAY_TIMEOUT_SECONDS: float = 10.0
    BOOTSTRAP_ADMIN_EMAIL: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

if settings.DATABASE_URL.startswith("postgresql://"):
    settings.DATABASE_URL = settings.DATABASE_URL.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )

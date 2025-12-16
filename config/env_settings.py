from typing import Optional
from loguru import logger
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SuperUserSettings(BaseSettings):
    username: str = Field(default="superuser", alias="SUPERUSER_USERNAME")
    password: str = Field(default="superuser", alias="SUPERUSER_PASSWORD")


class GRPCSettings(BaseSettings):
    host: str = Field(default="0.0.0.0", alias="GRPC_HOST")
    port: str = Field(default="50051", alias="GRPC_PORT")


class SecuritySettings(BaseSettings):
    secret_key: str = Field(
        default="your-secret-key-change-this-in-production", alias="SECRET_KEY"
    )
    algorithm: str = Field(default="HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    refresh_token_expire_minutes: int = Field(
        default=7 * 24 * 60, alias="REFRESH_TOKEN_EXPIRE_MINUTES"
    )


class LogSettings(BaseSettings):
    debug: bool = Field(default=True, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    enable_grpc_access_log: bool = Field(default=True, alias="ENABLE_GRPC_ACCESS_LOG")


class RedisSettings(BaseSettings):
    host: str = Field(default="localhost", alias="REDIS_HOST")
    port: int = Field(default=6379, alias="REDIS_PORT")
    db: int = Field(default=0, alias="REDIS_DB")
    max_connections: int = Field(default=10, alias="REDIS_MAX_CONNECTIONS")
    decode_responses: bool = Field(default=True, alias="REDIS_DECODE_RESPONSES")
    password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    default_timeout: int = Field(default=300, alias="REDIS_DEFAULT_TIMEOUT")

    @property
    def url(self) -> str:
        """Генерирует URL для подключения к Redis.

        Returns:
            str: Redis URL в формате redis://[user:password@]host:port/db

        Example:
            >>> redis = RedisSettings()
            >>> print(redis.url)
            'redis://localhost:6379/0'
        """
        if self.password is None:
            return f"redis://{self.host}:{self.port}/{self.db}"

        return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)
    db: str = Field(default="postgres", alias="POSTGRES_DB")
    user: str = Field(default="postgres", alias="POSTGRES_USER")
    password: str = Field(default="password", alias="POSTGRES_PASSWORD")
    host: str = Field(default="localhost", alias="POSTGRES_HOST")
    port: int = Field(default=5432, alias="POSTGRES_PORT")
    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)
    echo: bool = Field(default=False)

    @property
    def url_asyncpg(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.db}"

    @property
    def url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.db}"


class Settings(BaseSettings):
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    log: LogSettings = Field(default_factory=LogSettings)
    postgres: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    superuser: SuperUserSettings = Field(default_factory=SuperUserSettings)
    grpc: GRPCSettings = Field(default_factory=GRPCSettings)


settings = Settings()

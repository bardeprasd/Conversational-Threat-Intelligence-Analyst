"""Validated environment configuration for models and intelligence providers."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Resolve from this module so startup location cannot select a root-level file.
        env_file=BACKEND_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-5.6-luna", alias="OPENAI_MODEL")
    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    otx_api_key: str | None = Field(default=None, alias="OTX_API_KEY")
    shodan_api_key: str | None = Field(default=None, alias="SHODAN_API_KEY")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    live_api_timeout_seconds: float = Field(
        default=8.0, alias="LIVE_API_TIMEOUT_SECONDS", gt=0
    )
    max_turns: int = Field(default=6, alias="MAX_TURNS", ge=1, le=12)
    thread_history_limit: int = Field(
        default=50, alias="THREAD_HISTORY_LIMIT", ge=1, le=200
    )
    rate_limit_requests: int = Field(default=20, alias="RATE_LIMIT_REQUESTS", ge=1)
    rate_limit_window_seconds: int = Field(
        default=60, alias="RATE_LIMIT_WINDOW_SECONDS", ge=1
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    allowed_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="ALLOWED_ORIGINS",
    )
    allowed_origin_regex: str | None = Field(
        default=r"^https?://(localhost|127\.0\.0\.1):\d+$",
        alias="ALLOWED_ORIGIN_REGEX",
    )

    @property
    def origins(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

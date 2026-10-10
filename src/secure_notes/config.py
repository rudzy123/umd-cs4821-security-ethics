"""Process configuration. Secrets come from the environment, never from source."""

import os

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Lab settings loaded from the process environment.

    ``NOTES_SECRET_KEY`` has no default. The process fails closed when it is
    missing. The value is a server secret used to hash bearer tokens before
    storage. It is not an encryption key for note contents.
    """

    model_config = SettingsConfigDict(env_prefix="NOTES_", extra="ignore")

    secret_key: str = Field(min_length=32)
    database_path: str = "notes-lab.db"
    token_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    rate_limit_requests: int = Field(default=30, ge=1, le=10_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)

    @field_validator("secret_key")
    @classmethod
    def normalize_secret_key(cls, value: str) -> str:
        stripped = value.strip()
        if len(stripped) < 32:
            raise ValueError("must be at least 32 characters")
        if "\x00" in stripped:
            raise ValueError("must not contain a NUL byte")
        return stripped

    @field_validator("database_path")
    @classmethod
    def normalize_database_path(cls, value: str) -> str:
        stripped = value.strip()
        if stripped == "" or "\x00" in stripped:
            raise ValueError("database path is empty or invalid")
        return stripped


def load_settings() -> Settings:
    """Load settings, refusing to start without a server secret."""

    raw_secret = os.environ.get("NOTES_SECRET_KEY")
    if raw_secret is None or raw_secret.strip() == "":
        raise RuntimeError(
            "NOTES_SECRET_KEY is required. Generate one with "
            "secrets.token_urlsafe(32) and export it for this process only. "
            "Do not commit it, and do not reuse a real production secret."
        )
    return Settings(secret_key=raw_secret)

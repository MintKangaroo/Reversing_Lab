"""Runtime configuration — the single source of tunable settings.

Values are read from environment variables (prefix ``RLAB_``) with safe defaults, so
the platform runs out of the box in development and is fully configurable in
production without code changes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings. Override any field via ``RLAB_<FIELD>`` env vars."""

    model_config = SettingsConfigDict(env_prefix="RLAB_", env_file=".env", extra="ignore")

    # --- Storage -----------------------------------------------------------------
    database_url: str = Field(
        default="sqlite:///./reversing_lab.db",
        description="SQLAlchemy database URL.",
    )
    storage_dir: Path = Field(
        default=Path("./data/binaries"),
        description="Directory where uploaded binary bytes are stored on disk.",
    )

    # --- Upload limits (security) ------------------------------------------------
    max_upload_bytes: int = Field(
        default=32 * 1024 * 1024,  # 32 MiB
        description="Reject uploads larger than this to bound resource usage.",
    )

    # --- Analysis bounds (DoS protection) ----------------------------------------
    max_disassembly_instructions: int = Field(
        default=20_000,
        description="Hard cap on instructions decoded in a single disassembly request.",
    )
    max_cfg_instructions: int = Field(
        default=8_000,
        description="Hard cap on instructions considered when building a CFG.",
    )
    max_strings: int = Field(
        default=10_000,
        description="Hard cap on extracted strings returned per request.",
    )
    hex_page_size: int = Field(
        default=1024,
        description="Bytes per page returned by the hex viewer.",
    )

    # --- HTTP --------------------------------------------------------------------
    cors_origins: list[str] = Field(
        default=["http://localhost:5173", "http://127.0.0.1:5173"],
        description="Allowed CORS origins for the front-end dev server.",
    )
    log_level: str = Field(default="INFO", description="Root log level.")

    # --- Integrations ------------------------------------------------------------
    radare2_path: str = Field(default="r2", description="radare2 executable name/path.")
    integration_timeout_seconds: float = Field(
        default=30.0, description="Timeout for external-tool subprocess calls."
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()

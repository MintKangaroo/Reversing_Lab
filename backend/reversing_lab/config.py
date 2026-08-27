"""Runtime configuration — the single source of tunable settings.

Values are read from environment variables (prefix ``RLAB_``) with safe defaults, so
the platform runs out of the box in development and is fully configurable in
production without code changes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
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
    max_memory_dump_bytes: int = Field(
        default=512 * 1024 * 1024,
        description="Reject memory dumps larger than this bound.",
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
    max_function_scan_instructions: int = Field(
        default=50_000,
        description="Hard cap on instructions scanned while recovering functions.",
    )
    max_instructions_per_function: int = Field(
        default=4_000,
        description="Hard cap on instructions attributed to one recovered function.",
    )
    max_functions: int = Field(
        default=5_000,
        description="Hard cap on recovered functions per sample.",
    )
    max_cfg_nodes: int = Field(
        default=2_000,
        description="Hard cap on basic blocks exposed for one CFG.",
    )
    max_call_graph_nodes: int = Field(
        default=2_000,
        description="Hard cap on nodes exposed in a call graph.",
    )
    max_dynamic_events: int = Field(
        default=100_000,
        description="Hard cap on dynamic events accepted from a sandbox provider.",
    )
    max_memory_processes: int = Field(
        default=10_000,
        ge=1,
        le=100_000,
        description="Hard cap on normalized processes retained from a memory provider.",
    )
    max_memory_modules: int = Field(
        default=50_000,
        ge=1,
        le=500_000,
        description="Hard cap on normalized loaded modules retained per dump.",
    )
    max_memory_regions: int = Field(
        default=100_000,
        ge=1,
        le=1_000_000,
        description="Hard cap on normalized memory regions retained per dump.",
    )
    max_memory_network_records: int = Field(
        default=50_000,
        ge=1,
        le=500_000,
        description="Hard cap on normalized network records retained per dump.",
    )
    max_memory_handles: int = Field(
        default=100_000,
        ge=1,
        le=1_000_000,
        description="Hard cap on normalized handle records retained per dump.",
    )
    max_memory_threads: int = Field(
        default=200_000,
        ge=1,
        le=2_000_000,
        description="Hard cap on normalized thread records retained per dump.",
    )
    max_memory_region_extract_bytes: int = Field(
        default=1024 * 1024,
        ge=4096,
        le=16 * 1024 * 1024,
        description=(
            "Maximum size of one explicitly requested memory-region extraction."
        ),
    )
    max_memory_findings: int = Field(
        default=1_000,
        ge=1,
        le=100_000,
        description="Hard cap on heuristic memory findings retained per dump.",
    )
    max_audit_export_records: int = Field(
        default=100_000,
        ge=1,
        le=1_000_000,
        description=(
            "Maximum audit events in one streaming export; narrower time filters "
            "are required above this bound."
        ),
    )
    max_analysis_seconds: float = Field(
        default=300.0,
        description="Default wall-clock limit for a background analysis job.",
    )
    max_concurrent_jobs: int = Field(
        default=2,
        description="Maximum number of in-process background analysis jobs.",
    )
    max_yara_matches: int = Field(
        default=1_000,
        description="Maximum YARA matches retained for one analysis.",
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

    # --- Authentication (disabled for backward-compatible local development) -----
    auth_mode: Literal["disabled", "api_key"] = Field(
        default="disabled",
        description="Enable digest-backed bearer API keys when set to 'api_key'.",
    )
    auth_api_key_hashes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "SHA-256 digest to 'principal:role' mapping; raw bearer keys are never "
            "stored in configuration. Roles: viewer, analyst, admin."
        ),
    )

    # --- Integrations ------------------------------------------------------------
    radare2_path: str = Field(default="r2", description="radare2 executable name/path.")
    upx_path: str = Field(default="upx", description="UPX executable name/path.")
    volatility_path: str = Field(
        default="vol", description="Volatility 3 executable name/path."
    )

    # --- Dynamic analysis (disabled unless every guardrail is configured) --------
    sandbox_provider: str = Field(
        default="disabled",
        description="Sandbox provider name. 'disabled' never executes a sample.",
    )
    sandbox_worker_url: str | None = Field(
        default=None,
        description="Out-of-process isolated worker endpoint.",
    )
    sandbox_workspace_dir: Path | None = Field(
        default=None,
        description="Private writable workspace managed by the sandbox worker.",
    )
    sandbox_timeout_seconds: int = Field(default=60, ge=1, le=3_600)
    sandbox_memory_mb: int = Field(default=512, ge=64, le=65_536)
    sandbox_cpu_count: float = Field(default=1.0, gt=0, le=32)
    sandbox_process_limit: int = Field(default=32, ge=1, le=4_096)
    sandbox_network_policy: str = Field(
        default="blocked",
        description="Sandbox network policy; blocked is the secure default.",
    )
    integration_timeout_seconds: float = Field(
        default=30.0, description="Timeout for external-tool subprocess calls."
    )
    max_decompiler_seconds: float = Field(
        default=45.0,
        description="Hard timeout for one external decompiler request.",
    )
    max_external_output_bytes: int = Field(
        default=2 * 1024 * 1024,
        description="Maximum structured output accepted from an external tool.",
    )

    @field_validator("auth_api_key_hashes")
    @classmethod
    def validate_api_key_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        allowed_roles = {"viewer", "analyst", "admin"}
        for digest, descriptor in value.items():
            invalid_digest = len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            )
            if invalid_digest:
                raise ValueError("Authentication key digests must be lowercase SHA-256.")
            principal, separator, role = descriptor.rpartition(":")
            valid_principal = (
                1 <= len(principal) <= 128
                and all(
                    character.isascii()
                    and (character.isalnum() or character in "._@-")
                    for character in principal
                )
            )
            if not separator or not valid_principal or role not in allowed_roles:
                raise ValueError(
                    "Authentication descriptors must use 'principal:viewer|analyst|admin'."
                )
        return value

    @model_validator(mode="after")
    def require_keys_when_auth_enabled(self) -> "Settings":
        if self.auth_mode == "api_key" and not self.auth_api_key_hashes:
            raise ValueError(
                "API-key authentication requires at least one digest mapping."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()

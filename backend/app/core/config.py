"""Application Configuration Module for PhishGuard.

Loads and validates environment variables using Pydantic Settings.
"""

from pathlib import Path
from typing import Any, List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project Root Directory Resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class Settings(BaseSettings):
    """PhishGuard Runtime Configuration Settings."""

    # Application Metadata
    APP_NAME: str = "PhishGuard Phishing Threat Analysis Platform"
    APP_VERSION: str = "1.0.0"
    PHISHGUARD_ENV: str = "development"
    DEBUG: bool = True

    # Server Network Binding (Loopback Only)
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Allowed Origins for CORS and Origin/Referer State-Changing Verification
    ALLOWED_ORIGINS: List[str] = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]

    # Allowed Host Headers for TrustedHostMiddleware
    ALLOWED_HOSTS: List[str] = [
        "127.0.0.1",
        "localhost",
        "127.0.0.1:8000",
        "localhost:8000",
        "testserver",
    ]

    # Database Configuration (SQLite default with WAL mode)
    DATABASE_URL: str = f"sqlite:///{PROJECT_ROOT}/data/phishguard.db"

    # Filesystem Storage Directories
    EVIDENCE_DIR: Path = Field(default=PROJECT_ROOT / "data" / "evidence")
    REPORTS_DIR: Path = Field(default=PROJECT_ROOT / "data" / "reports")
    PSL_FILE_PATH: Path = Field(default=PROJECT_ROOT / "data" / "psl" / "public_suffix_list.dat")

    def model_post_init(self, __context: Any) -> None:
        """Ensure filesystem directories are strictly absolute against PROJECT_ROOT."""
        if not self.EVIDENCE_DIR.is_absolute():
            object.__setattr__(self, "EVIDENCE_DIR", (PROJECT_ROOT / self.EVIDENCE_DIR).resolve())
        if not self.REPORTS_DIR.is_absolute():
            object.__setattr__(self, "REPORTS_DIR", (PROJECT_ROOT / self.REPORTS_DIR).resolve())
        if not self.PSL_FILE_PATH.is_absolute():
            object.__setattr__(self, "PSL_FILE_PATH", (PROJECT_ROOT / self.PSL_FILE_PATH).resolve())

    # Security & Upload Boundaries
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # CSRF & Custom Client Header
    # Note: In a local single-user architecture, requiring a custom non-standard client header
    # (e.g. X-PhishGuard-Client) prevents ambient HTML form submissions from cross-origin drive-by sites.
    # It does not substitute for session-bound tokens in multi-user authenticated environments.
    CSRF_CLIENT_HEADER: str = "X-PhishGuard-Client"
    CSRF_EXPECTED_VALUE: str = "web-console"

    # Retention Policy
    EVIDENCE_RETENTION_DAYS: int = 90

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


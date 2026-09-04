"""Application configuration and local data locations (PRD §9.3, §13.1)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_dir() -> Path:
    """Return %LOCALAPPDATA%\\ReconScope on Windows, else a per-user fallback."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "ReconScope"
    return Path.home() / ".reconscope"


class Settings(BaseSettings):
    """Runtime settings. Override via env vars prefixed ``RECONSCOPE_``."""

    model_config = SettingsConfigDict(env_prefix="RECONSCOPE_", extra="ignore")

    # The backend binds only to loopback (PRD §13.1). Remote binding is not
    # available in v1.
    host: str = "127.0.0.1"
    # Port 0 asks the OS for a free port; the launcher pins the chosen one.
    port: int = 0

    data_dir: Path = _default_data_dir()

    # Enable OpenAPI docs only when explicitly turned on (PRD §12.4).
    enable_docs: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "reconscope.db"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "data"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()

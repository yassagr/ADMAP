"""
Module   : admap_m1.core.config
Version  : 3.0.0
Dépend   : [pydantic_settings]

Configuration centralisée via pydantic-settings.
Toutes les variables d'environnement portent le préfixe ``ADMAP_M1_``.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration globale du module M1 ADMAP.

    Les valeurs sont chargées depuis les variables d'environnement
    préfixées par ``ADMAP_M1_`` et depuis un fichier ``.env`` optionnel.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ADMAP_M1_",
        case_sensitive=False,
    )

    # ── API ─────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1
    ALLOWED_ORIGINS: list[str] = ["*"]
    DEBUG: bool = False

    # ── Fichiers ────────────────────────────────────────────────────────────
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_EXTENSIONS: set[str] = {
        ".exe", ".dll", ".bin", ".dat", ".pdf", ".doc", ".docx",
        ".xls", ".xlsx", ".docm", ".xlsm", ".zip", ".gz", ".7z",
        ".tar", ".txt", ".log", ".csv", ".json", ".xml", ".html",
        ".ps1", ".bat", ".vbs", ".js", ".hta", ".sh", ".elf", ".so",
    }
    TEMP_DIR: Path = Path("/tmp/admap_m1")

    # ── Pipeline ────────────────────────────────────────────────────────────
    MAX_RECURSION_DEPTH: int = 3
    MIN_CONFIDENCE_THRESHOLD: int = 20
    JOB_TTL_HOURS: int = 24
    MAX_QUEUE_SIZE: int = 100
    DEOBFUSCATION_TIMEOUT_SECONDS: int = 30
    ARCHIVE_TIMEOUT_SECONDS: int = 60

    # ── VirusTotal ──────────────────────────────────────────────────────────
    VT_API_KEY: str = ""
    VT_IS_PREMIUM: bool = False
    VT_MAX_PER_TYPE: int = 5
    VT_CACHE_TTL_HOURS: int = 4
    VT_TIMEOUT_SECONDS: int = 10
    VT_MAX_RETRIES: int = 3

    # ── Logging ─────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" | "console"

    # ── Archive protection ──────────────────────────────────────────────────
    MAX_ARCHIVE_DEPTH: int = 5
    MAX_EXTRACTED_SIZE_MB: int = 200


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne l'instance singleton de Settings.

    Returns:
        Instance de Settings chargée depuis l'environnement.
    """
    return Settings()

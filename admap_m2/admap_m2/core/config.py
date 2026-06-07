"""
Module   : admap_m2.core.config
Version  : 1.0.0
Dépend   : [pydantic_settings, functools]
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ADMAP_M2_",
        case_sensitive=False,
    )

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8001
    API_WORKERS: int = 1
    ALLOWED_ORIGINS: list[str] = ["*"]
    DEBUG: bool = False

    # Fichiers PCAP
    MAX_PCAP_SIZE_MB: int = 500
    TEMP_DIR: Path = Path("/tmp/admap_m2")
    ALLOWED_EXTENSIONS: set[str] = {".pcap", ".pcapng", ".cap", ".dump"}

    # Pipeline
    ANALYSIS_TIMEOUT_SECONDS: int = 300
    MAX_FLOWS: int = 100000
    JOB_TTL_HOURS: int = 24
    MAX_QUEUE_SIZE: int = 50

    # Détecteurs — seuils
    MIN_CONFIDENCE_THRESHOLD: int = 20
    BEACONING_MIN_OCCURRENCES: int = 5
    BEACONING_JITTER_TOLERANCE: float = 0.15
    DGA_ENTROPY_THRESHOLD: float = 3.5
    DGA_MIN_DOMAIN_LENGTH: int = 12
    DNS_TUNNEL_QUERY_LENGTH: int = 50
    DNS_TUNNEL_MIN_QUERIES: int = 10
    PORT_SCAN_THRESHOLD: int = 20

    # M1 intégration
    M1_BUNDLE_DEFAULT_PATH: str = ""

    # GeoIP (optionnel)
    GEOIP_DB_PATH: str = ""

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne le singleton Settings (caché via lru_cache)."""
    return Settings()

from __future__ import annotations
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ADMAP_M4_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Serveur
    host: str = "0.0.0.0"
    port: int = 8003
    workers: int = 1
    debug: bool = False
    version: str = "1.0.0"

    # Pipeline
    max_concurrent_jobs: int = 5
    job_timeout_seconds: int = 300

    # DBSCAN (seuils dynamiques, jamais hardcodés dans le code métier)
    dbscan_epsilon: float = Field(default=0.3, ge=0.0, le=1.0)
    dbscan_min_samples: int = Field(default=2, ge=1)

    # Filtrage TTP
    min_confidence_score: int = Field(default=20, ge=0, le=100)
    min_techniques_per_profile: int = Field(default=1, ge=1)

    # Intégrations amont
    m1_base_url: str = "http://localhost:8000"
    m2_base_url: str = "http://localhost:8001"
    m3_base_url: str = "http://localhost:8002"

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class M5Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="M5_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    host: str = "0.0.0.0"
    port: int = 8004
    debug: bool = False
    version: str = "1.0.0"

    # Paths
    apt_kb_path: Path = Path("data/apt_kb.json")
    model_store_path: Path = Path("models_store")
    xgb_model_filename: str = "xgb_attributor.joblib"

    # Attribution
    top_k_candidates: int = 3           # Nombre de candidats APT retournés
    min_confidence_threshold: float = 10.0  # Score minimum pour inclure un candidat
    cosine_similarity_weight: float = 0.4   # Poids similarité cosinus dans le score final
    xgb_weight: float = 0.6                 # Poids XGBoost dans le score final

    # Feature engineering
    max_techniques_per_cluster: int = 10
    ssdeep_similarity_threshold: int = 50   # Seuil SSDeep fuzzy match (0-100)

    # Job queue
    max_queue_size: int = 100
    job_timeout_seconds: int = 300

    @property
    def xgb_model_path(self) -> Path:
        return self.model_store_path / self.xgb_model_filename


@lru_cache
def get_settings() -> M5Settings:
    return M5Settings()

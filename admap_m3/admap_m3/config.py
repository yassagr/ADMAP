"""
Module   : admap_m3.config
Version  : 1.0.0
Dépend   : [pydantic-settings]

Configuration centralisée du microservice M3.
Toutes les valeurs sont surchargeables via variables d'environnement
préfixées ``ADMAP_M3_`` ou via un fichier ``.env``.
"""
from __future__ import annotations

from functools import lru_cache


from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Paramètres de configuration pour ADMAP M3."""

    model_config = SettingsConfigDict(env_prefix="ADMAP_M3_", env_file=".env")

    # ── Serveur ──────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8002
    debug: bool = False
    version: str = "1.0.0"

    # ── Corpus ───────────────────────────────────────────────────────────
    corpus_dir: str = "/tmp/admap_m3/corpus"
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_corpus_files: int = 500

    # ── Algorithme TF-IDF discriminant ───────────────────────────────────
    delta_threshold: float = 0.30
    min_token_length: int = 6
    max_tokens_per_rule: int = 20
    min_tokens_per_rule: int = 3
    min_df_malware: int = 2
    max_df_benign: int = 0
    ngram_size: int = 4

    # ── Intégration M1 ──────────────────────────────────────────────────
    m1_base_url: str = "http://localhost:8000"
    m1_integration_enabled: bool = True
    m1_timeout_seconds: int = 30

    # ── Output ──────────────────────────────────────────────────────────
    output_dir: str = "/tmp/admap_m3/output"
    tlp_default: str = "TLP:AMBER"

    # ── Worker ──────────────────────────────────────────────────────────
    max_concurrent_jobs: int = 3
    job_ttl_seconds: int = 3600


@lru_cache
def get_settings() -> Settings:
    """Retourne l'instance singleton de la configuration."""
    return Settings()

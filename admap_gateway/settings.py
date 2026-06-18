from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    m1_url: str = "http://localhost:8000"
    m2_url: str = "http://localhost:8001"
    m3_url: str = "http://localhost:8002"
    m4_url: str = "http://localhost:8003"
    m5_url: str = "http://localhost:8004"

    # Timeout for proxy requests (seconds)
    proxy_timeout: float = 30.0
    # Timeout for long-running pipelines
    pipeline_timeout: float = 300.0


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (ADMAP invariant: @lru_cache)."""
    return Settings()

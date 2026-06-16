from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import structlog
from fastapi import FastAPI

from admap_m5.config import get_settings
from admap_m5.api.routes import router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan FastAPI — initialise la queue et les composants dans app.state."""
    settings = get_settings()
    logger.info("m5.startup", port=settings.port, version=settings.version)

    # Job queue dans app.state (jamais de variable globale mutable)
    app.state.job_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.max_queue_size)
    app.state.jobs: dict = {}
    app.state.settings = settings

    logger.info("m5.ready", queue_maxsize=settings.max_queue_size)
    yield

    logger.info("m5.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ADMAP M5 — Attribution",
        description="Microservice d'attribution APT via XGBoost + similarité cosinus",
        version=settings.version,
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()

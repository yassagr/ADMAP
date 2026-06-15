from __future__ import annotations
import asyncio
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator
import structlog
import structlog.stdlib
from fastapi import FastAPI
from admap_m4.config import get_settings
from admap_m4.api.routes import router
from admap_m4.worker import AsyncWorker

# Configuration structlog -- JSON sur stderr
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)
logger = structlog.get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise la job queue et les workers dans le lifespan FastAPI."""
    settings = get_settings()
    queue: asyncio.Queue = asyncio.Queue(maxsize=settings.max_concurrent_jobs * 2)
    app.state.job_queue = queue
    app.state.jobs: dict = {}
    app.state.settings = settings

    worker = AsyncWorker(queue=queue, jobs=app.state.jobs, settings=settings)
    # Using asyncio.get_running_loop() implicitly inside asyncio.create_task or explicitly
    task = asyncio.create_task(worker.run())
    app.state.worker_task = task

    logger.info("m4_startup_complete", port=settings.port, version=settings.version)

    yield  # application en cours d'exécution

    # Arrêt propre
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("m4_shutdown_complete")

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ADMAP M4 — APT Mapper",
        version=settings.version,
        description="Module de clustering et mapping MITRE ATT&CK",
        lifespan=lifespan,
    )
    app.include_router(router, prefix="/api/v1")
    return app

app = create_app()

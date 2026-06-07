"""
Module   : admap_m2.api.main
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.core.config, admap_m2.core.logging,
            admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from admap_m2.api.routers import analyze, export, jobs
from admap_m2.core.config import get_settings
from admap_m2.core.logging import get_logger, setup_logging
from admap_m2.pipeline.job_queue import JobQueue

try:
    from admap_m2.parsers.pcap_parser import SCAPY_AVAILABLE
except Exception:
    SCAPY_AVAILABLE = False

try:
    from admap_m1.models.ioc import IOCBundle  # noqa: F401
    M1_AVAILABLE = True
except ImportError:
    M1_AVAILABLE = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger = get_logger("api.lifespan")
    logger.info("admap_m2_starting", port=settings.API_PORT)

    queue = JobQueue()
    # start_workers() est sync mais doit être appelé depuis un contexte async
    # pour que asyncio.create_task() ait accès à la boucle active
    queue.start_workers(num_workers=settings.API_WORKERS)
    app.state.job_queue = queue  # R6 : attribut exact 'job_queue'

    yield

    logger.info("admap_m2_shutting_down")
    await queue.stop_workers()


app = FastAPI(
    title="ADMAP M2 — C2 Detector",
    version="1.0.0",
    description="Module d'analyse comportementale (C2, DGA, Beaconing) via PCAP.",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Les routers sont inclus avec le prefix /api/v1
app.include_router(analyze.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str]:
    """R7 : retourne status + version exactement."""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/ready", tags=["system"])
async def readiness_check(request: Request) -> dict[str, object]:
    """R8 : retourne capacités du module."""
    queue: JobQueue = request.app.state.job_queue
    return {
        "status": "ok",
        "version": "1.0.0",
        "queue_size": queue.queue_size,
        "scapy_available": SCAPY_AVAILABLE,
        "m1_integration": M1_AVAILABLE,
    }

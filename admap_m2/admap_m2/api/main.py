"""
Module   : admap_m2.api.main
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.core.config, admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from admap_m2.api.routers import analyze, export, jobs
from admap_m2.core.config import get_settings
from admap_m2.core.logging import get_logger, setup_logging
from admap_m2.pipeline.job_queue import JobQueue
from admap_m2.parsers.pcap_parser import SCAPY_AVAILABLE

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
    queue.start_workers(num_workers=settings.API_WORKERS)  # synchrone après correction
    app.state.job_queue = queue  # R6 : attribut exact

    yield

    logger.info("admap_m2_shutting_down")
    await queue.stop_workers()


app = FastAPI(
    title="ADMAP M2 - C2 Detector",
    version="1.0.0",
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

app.include_router(analyze.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")


@app.get("/health", tags=["system"])
async def health_check() -> dict:
    """Retourne le statut de santé du service."""
    return {"status": "ok", "version": "1.0.0"}  # R7 exact


@app.get("/ready", tags=["system"])
async def readiness_check(request: Request) -> dict:
    """Retourne les capacités et l'état de préparation du service."""
    queue: JobQueue = request.app.state.job_queue
    return {
        "status": "ok",
        "version": "1.0.0",
        "queue_size": queue.queue_size,
        "scapy_available": SCAPY_AVAILABLE,
        "m1_integration": M1_AVAILABLE,
    }  # R8 exact

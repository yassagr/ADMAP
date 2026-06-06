"""
Module   : admap_m2.api.main
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.core.config]
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from admap_m2.api.routers import analyze, export, jobs
from admap_m2.core.config import get_settings
from admap_m2.core.logging import get_logger, setup_logging
from admap_m2.pipeline.job_queue import JobQueue


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger = get_logger("api.main")
    
    logger.info("Starting M2 API")
    queue = JobQueue(settings)
    app.state.queue = queue
    await queue.start_workers(settings.API_WORKERS)
    
    yield
    
    logger.info("Stopping M2 API")
    await queue.stop_workers()


app = FastAPI(
    title="ADMAP M2 - C2 Detector API",
    version="1.0.0",
    lifespan=lifespan
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(jobs.router)
app.include_router(export.router)

@app.get("/health", tags=["system"])
async def health_check():
    return {"status": "ok", "module": "admap_m2"}

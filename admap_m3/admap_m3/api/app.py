"""
Module   : admap_m3.api.app
Version  : 1.0.0
Dépend   : [fastapi, asyncio, structlog]

Point d'entrée principal de l'API FastAPI M3.
Configure le lifespan (queue + worker), le CORS, et inclut les routeurs.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from admap_m3.api.routes import export, generate, health, jobs
from admap_m3.api.worker import job_worker
from admap_m3.config import get_settings
from admap_m3.models.job import GenerationJob

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gère le démarrage et l'arrêt du microservice M3.

    - STARTUP : initialise la job queue, le store de jobs, et lance le
      worker en tâche de fond.
    - SHUTDOWN : annule le worker proprement.
    """
    settings = get_settings()

    # Initialisation de la queue dans app.state (JAMAIS en global)
    app.state.job_queue = asyncio.Queue()
    app.state.jobs: dict[str, GenerationJob] = {}
    app.state.results: dict[str, object] = {}
    app.state.settings = settings

    # Lancer le worker en tâche de fond
    worker_task: asyncio.Task[None] = asyncio.create_task(job_worker(app))
    app.state.worker_task = worker_task

    logger.info(
        "admap_m3_startup",
        port=settings.port,
        version=settings.version,
        max_concurrent_jobs=settings.max_concurrent_jobs,
    )

    yield

    # SHUTDOWN
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    logger.info("admap_m3_shutdown")


# ── Application FastAPI ──────────────────────────────────────────────────

app: FastAPI = FastAPI(
    title="ADMAP M3 — YARA Signature Generator",
    description="API de génération automatique de règles YARA depuis un corpus malware/bénin",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routeurs
app.include_router(health.router)
app.include_router(generate.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")

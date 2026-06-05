"""
Module   : admap_m1.api.main
Version  : 3.0.0
Dépend   : [fastapi, uvicorn]

Point d'entrée principal pour l'API M1.
Configure FastAPI, le middleware CORS, l'injection de dépendances et le cycle de vie.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from admap_m1.api.dependencies import get_queue
from admap_m1.api.routers import analyze, export, jobs
from admap_m1.core.config import get_settings
from admap_m1.core.logging import get_logger, setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gère le démarrage et l'arrêt des services asynchrones (Workers)."""
    settings = get_settings()
    
    # Configuration du logging structlog
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger = get_logger("api.lifespan")
    logger.info("admap_m1_api_starting", port=settings.API_PORT, workers=settings.API_WORKERS)

    # Démarrage de la JobQueue
    queue = get_queue()
    queue.start_workers(num_workers=settings.API_WORKERS)
    
    yield  # L'application tourne ici
    
    # Arrêt
    logger.info("admap_m1_api_shutting_down")
    await queue.stop_workers()


# Création de l'application FastAPI
app = FastAPI(
    title="ADMAP M1 - IOC Extractor",
    description="API du module d'extraction statique d'indicateurs de compromission",
    version="3.0.0",
    lifespan=lifespan,
)

# Configuration CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusion des routeurs
app.include_router(analyze.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")


@app.get("/health", tags=["System"])
async def health_check():
    """Vérifie l'état de l'API M1."""
    return {"status": "ok", "service": "ADMAP M1"}


if __name__ == "__main__":
    import uvicorn
    # Permet de lancer le fichier directement en développement
    current_settings = get_settings()
    uvicorn.run(
        "admap_m1.api.main:app",
        host=current_settings.API_HOST,
        port=current_settings.API_PORT,
        reload=current_settings.DEBUG,
        log_level=current_settings.LOG_LEVEL.lower()
    )

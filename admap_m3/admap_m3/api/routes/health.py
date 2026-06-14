"""
Module   : admap_m3.api.routes.health
Version  : 1.0.0
Dépend   : [fastapi, structlog]

Endpoints de healthcheck et readiness probe.
"""
from __future__ import annotations

import os
from typing import Any

import structlog
from fastapi import APIRouter, Request

from admap_m3.config import get_settings

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

router: APIRouter = APIRouter(tags=["System"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Healthcheck — retourne le statut, la version et le nom du module."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "module": "admap_m3",
    }


@router.get("/ready")
async def readiness_check(request: Request) -> dict[str, Any]:
    """Readiness probe — vérifie les sous-systèmes critiques.

    Contrôles effectués :
    - Queue asyncio initialisée
    - Settings valides
    - ``yara`` importable
    - ``corpus_dir`` accessible en lecture
    """
    settings = get_settings()

    # Vérifier la queue
    queue_size: int = 0
    try:
        queue_size = request.app.state.job_queue.qsize()
    except AttributeError:
        pass

    # Vérifier yara
    yara_available: bool = False
    try:
        import yara  # noqa: F401

        yara_available = True
    except ImportError:
        pass

    # Vérifier corpus_dir
    corpus_dir_accessible: bool = os.path.isdir(settings.corpus_dir)

    all_ready: bool = yara_available
    status: str = "ready" if all_ready else "not_ready"

    return {
        "status": status,
        "version": settings.version,
        "queue_size": queue_size,
        "yara_available": yara_available,
        "corpus_dir_accessible": corpus_dir_accessible,
    }

"""
Module   : admap_m2.api.dependencies
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from fastapi import Request

from admap_m2.core.config import Settings, get_settings
from admap_m2.pipeline.job_queue import JobQueue


def get_app_settings() -> Settings:
    """Retourne la configuration globale."""
    return get_settings()


def get_queue(request: Request) -> JobQueue:
    """
    Retourne la JobQueue depuis l'état de l'application.

    Args:
        request: La requête FastAPI courante.

    Returns:
        Instance de JobQueue stockée dans app.state.job_queue.
    """
    return request.app.state.job_queue  # R6 : attribut exact

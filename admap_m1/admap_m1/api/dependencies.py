"""
Module   : admap_m1.api.dependencies
Version  : 3.0.0
Dépend   : [fastapi]

Dépendances injectables pour FastAPI (ex: accès à la JobQueue).
"""
from __future__ import annotations

from admap_m1.pipeline.job_queue import JobQueue, get_job_queue


def get_queue() -> JobQueue:
    """Fournit l'instance globale de la JobQueue aux routeurs FastAPI."""
    return get_job_queue()

"""
Module   : admap_m1.api.dependencies
Version  : 3.0.0
Dépend   : [fastapi, admap_m1.pipeline.job_queue]
"""
from __future__ import annotations

from fastapi import Request

from admap_m1.pipeline.job_queue import JobQueue


def get_queue(request: Request) -> JobQueue:
    """Fournit l'instance JobQueue depuis app.state (injectée au lifespan)."""
    return request.app.state.job_queue

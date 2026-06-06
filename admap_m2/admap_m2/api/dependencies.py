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
    return get_settings()


def get_queue(request: Request) -> JobQueue:
    return request.app.state.queue

"""
Module   : admap_m2.api.routers.jobs
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.models.job]
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from admap_m2.api.dependencies import get_queue
from admap_m2.models.job import AnalysisJob
from admap_m2.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=AnalysisJob)
async def get_job_status(job_id: str, queue: JobQueue = Depends(get_queue)) -> AnalysisJob:
    """Récupère le statut d'un job d'analyse."""
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.delete("/{job_id}")
async def cancel_job(job_id: str, queue: JobQueue = Depends(get_queue)) -> dict:
    """Annule un job si possible."""
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # Actually, we don't have true cancellation in queue without searching inside queue
    raise HTTPException(status_code=501, detail="Job cancellation not implemented yet")

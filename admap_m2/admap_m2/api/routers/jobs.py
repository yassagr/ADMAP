"""
Module   : admap_m2.api.routers.jobs
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.models.job, admap_m2.models.alert,
            admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from admap_m2.api.dependencies import get_queue
from admap_m2.core.exceptions import JobNotFoundError
from admap_m2.models.alert import AlertBundle
from admap_m2.models.job import AnalysisJob
from admap_m2.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=AnalysisJob)
async def get_job_status(
    job_id: UUID, queue: JobQueue = Depends(get_queue)
) -> AnalysisJob:
    """
    Récupère le statut et la progression d'un job d'analyse.

    Args:
        job_id: UUID du job.

    Returns:
        AnalysisJob avec status, progress, current_stage.

    Raises:
        HTTPException 404: Si le job n'existe pas.
    """
    try:
        return queue.get_job_status(job_id)
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/{job_id}/result", response_model=AlertBundle)
async def get_job_result(
    job_id: UUID, queue: JobQueue = Depends(get_queue)
) -> AlertBundle:
    """
    Récupère l'AlertBundle complet d'un job terminé.

    Args:
        job_id: UUID du job.

    Returns:
        AlertBundle complet.

    Raises:
        HTTPException 404: Job introuvable ou résultat non disponible.
    """
    try:
        result = queue.get_job_result(job_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Result not available for job {job_id} (still running or failed)",
            )
        return result
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.delete("/{job_id}")
async def cancel_job(
    job_id: UUID, queue: JobQueue = Depends(get_queue)
) -> dict:
    """
    Annule un job en attente ou en cours.

    Args:
        job_id: UUID du job à annuler.

    Returns:
        Dictionnaire avec le résultat de l'annulation.

    Raises:
        HTTPException 404: Job introuvable.
    """
    try:
        queue.get_job_status(job_id)  # Vérifie existence
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    cancelled = queue.cancel_job(job_id)
    return {"job_id": str(job_id), "cancelled": cancelled}

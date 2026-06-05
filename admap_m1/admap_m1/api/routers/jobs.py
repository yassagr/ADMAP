"""
Module   : admap_m1.api.routers.jobs
Version  : 3.0.0
Dépend   : [fastapi, admap_m1.models.job]

Routeur pour suivre l'état des jobs et récupérer les résultats complets.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from admap_m1.api.dependencies import get_queue
from admap_m1.core.exceptions import JobNotFoundError
from admap_m1.models.job import JobStatus
from admap_m1.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/jobs", tags=["Jobs"])


@router.get("/{job_id}")
async def get_job_status(job_id: UUID, queue: JobQueue = Depends(get_queue)):
    """Récupère l'état d'avancement d'un job d'analyse."""
    try:
        job = queue.get_job_status(job_id)
        return {
            "job_id": str(job.job_id),
            "filename": job.filename,
            "status": job.status,
            "progress": job.progress,
            "current_stage": job.current_stage,
            "error": job.error,
        }
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail="Job introuvable")


@router.get("/{job_id}/result")
async def get_job_result(job_id: UUID, queue: JobQueue = Depends(get_queue)):
    """Récupère le bundle IOC complet (format JSON interne) pour un job terminé."""
    try:
        job = queue.get_job_status(job_id)
        if job.status != JobStatus.COMPLETED:
            raise HTTPException(
                status_code=400,
                detail=f"L'analyse n'est pas terminée (Statut: {job.status})"
            )
            
        result = queue.get_job_result(job_id)
        if not result:
            raise HTTPException(status_code=404, detail="Résultat expiré ou introuvable")
            
        return result.model_dump(mode="json")
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail="Job introuvable")


@router.delete("/{job_id}")
async def cancel_job(job_id: UUID, queue: JobQueue = Depends(get_queue)):
    """Annule un job en cours d'exécution ou en attente."""
    if queue.cancel_job(job_id):
        return {"message": "Job annulé avec succès"}
    raise HTTPException(status_code=404, detail="Job introuvable ou déjà terminé")

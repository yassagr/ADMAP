"""
Module   : admap_m3.api.routes.jobs
Version  : 1.0.0
Dépend   : [fastapi, structlog]

Endpoints de gestion des jobs de génération.
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request

from admap_m3.models.job import GenerationJob, GenerationStatus

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

router: APIRouter = APIRouter(tags=["Jobs"])


@router.get("/jobs/{job_id}")
async def get_job_status(request: Request, job_id: str) -> dict[str, Any]:
    """Retourne le statut complet d'un job de génération."""
    jobs: dict[str, GenerationJob] = request.app.state.jobs

    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job introuvable : {job_id}")

    job: GenerationJob = jobs[job_id]
    return job.model_dump(mode="json")


@router.delete("/jobs/{job_id}")
async def cancel_job(request: Request, job_id: str) -> dict[str, str]:
    """Annule un job si son statut est PENDING.

    Si le job est déjà en cours ou terminé → 409 Conflict.
    """
    jobs: dict[str, GenerationJob] = request.app.state.jobs

    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job introuvable : {job_id}")

    job: GenerationJob = jobs[job_id]

    if job.status != GenerationStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Impossible d'annuler un job en statut '{job.status.value}'",
        )

    job.status = GenerationStatus.CANCELLED

    logger.info("job_cancelled", job_id=job_id)

    return {"status": "cancelled", "job_id": job_id}


@router.get("/jobs/{job_id}/result")
async def get_job_result(request: Request, job_id: str) -> Any:
    """Retourne le ``YaraRuleSet`` si le job est terminé.

    - 404 si le job n'existe pas.
    - 409 si le job n'est pas encore terminé.
    """
    jobs: dict[str, GenerationJob] = request.app.state.jobs

    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job introuvable : {job_id}")

    job: GenerationJob = jobs[job_id]

    if job.status != GenerationStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Job en statut '{job.status.value}' — résultat non disponible",
        )

    results: dict[str, object] = request.app.state.results
    if job_id not in results:
        raise HTTPException(status_code=404, detail="Résultat introuvable")

    return results[job_id]

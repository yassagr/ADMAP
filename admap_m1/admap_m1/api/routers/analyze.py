"""
Module   : admap_m1.api.routers.analyze
Version  : 3.0.0
Dépend   : [fastapi, admap_m1.models.job]

Routeur pour soumettre des fichiers à analyser.
"""
from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from admap_m1.api.dependencies import get_queue
from admap_m1.core.config import get_settings
from admap_m1.models.job import AnalysisOptions
from admap_m1.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("")
async def submit_analysis(
    file: Annotated[UploadFile, File(...)],
    enable_vt: Annotated[bool, Form()] = False,
    enable_deobfuscation: Annotated[bool, Form()] = True,
    queue: JobQueue = Depends(get_queue),
):
    """Soumet un fichier binaire pour extraction d'IOCs.

    L'analyse est traitée en arrière-plan.
    Retourne l'ID du job à interroger via /jobs/{job_id}.
    """
    settings = get_settings()

    # Validation de l'extension
    if file.filename:
        ext = f".{file.filename.split('.')[-1].lower()}"
        if ext not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=415, detail=f"Extension non supportée: {ext}")

    # Lecture sécurisée en mémoire (avec limite)
    try:
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=f"Fichier trop volumineux. Maximum: {settings.MAX_UPLOAD_SIZE_MB}MB"
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur de lecture: {e}")

    # Options d'analyse
    options = AnalysisOptions(
        enable_vt_enrichment=enable_vt,
        enable_deobfuscation=enable_deobfuscation,
    )

    # Soumission
    try:
        job = queue.submit_job(
            filename=file.filename or "unknown.bin",
            file_bytes=content,
            options=options,
        )
    except asyncio.QueueFull:
        raise HTTPException(
            status_code=503,
            detail="La file d'attente d'analyse est pleine. Réessayez plus tard."
        )

    return {
        "job_id": str(job.job_id),
        "status": job.status,
        "message": "Analyse acceptée et mise en file d'attente.",
        "status_url": f"/api/v1/jobs/{job.job_id}"
    }

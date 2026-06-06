"""
Module   : admap_m2.api.routers.analyze
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.models.job]
"""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from admap_m2.api.dependencies import get_queue, get_app_settings
from admap_m2.core.config import Settings
from admap_m2.models.job import AnalysisJob, AnalysisOptions
from admap_m2.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def analyze_pcap(
    file: UploadFile = File(...),
    options: AnalysisOptions = Depends(),
    queue: JobQueue = Depends(get_queue),
    settings: Settings = Depends(get_app_settings)
) -> dict:
    """Upload un fichier PCAP et lance l'analyse en asynchrone."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing")

    # Read file
    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # Validate size
    if len(file_bytes) > settings.MAX_PCAP_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size is {settings.MAX_PCAP_SIZE_MB}MB"
        )

    pcap_sha256 = hashlib.sha256(file_bytes).hexdigest()

    job = AnalysisJob(
        filename=file.filename,
        pcap_sha256=pcap_sha256,
        options=options
    )

    await queue.enqueue_job(job, file_bytes)

    return {
        "job_id": str(job.job_id),
        "status": job.status,
        "message": "Analysis job queued successfully"
    }

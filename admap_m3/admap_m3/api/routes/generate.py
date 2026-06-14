"""
Module   : admap_m3.api.routes.generate
Version  : 1.0.0
Dépend   : [fastapi, structlog]

Endpoint de lancement de génération YARA (POST /api/v1/generate)
et de consultation des capacités (GET /api/v1/generate/capabilities).
"""
from __future__ import annotations

import os
import tempfile
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, UploadFile

from admap_m3.config import get_settings
from admap_m3.models.job import GenerationJob, GenerationStatus

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

router: APIRouter = APIRouter(tags=["Generate"])


@router.post("/generate", status_code=202)
async def generate_rules(
    request: Request,
    malware_files: list[UploadFile],
    benign_files: list[UploadFile],
    m1_bundle: UploadFile | None = None,
    malware_family: str | None = None,
    mitre_attack: str | None = None,
) -> dict[str, Any]:
    """Lance une génération de règles YARA en arrière-plan.

    Accepte des fichiers malware et bénins en multipart/form-data.
    Retourne un job_id avec un statut 202 (Accepted).
    """
    settings = get_settings()
    max_per_side: int = settings.max_corpus_files // 2

    # Validation du nombre de fichiers
    if len(malware_files) > max_per_side:
        raise HTTPException(
            status_code=400,
            detail=f"Trop de fichiers malware ({len(malware_files)} > {max_per_side})",
        )
    if len(benign_files) > max_per_side:
        raise HTTPException(
            status_code=400,
            detail=f"Trop de fichiers bénins ({len(benign_files)} > {max_per_side})",
        )

    # Créer un répertoire temporaire pour le job
    job_dir: str = tempfile.mkdtemp(prefix="admap_m3_job_")
    malware_dir: str = os.path.join(job_dir, "malware")
    benign_dir: str = os.path.join(job_dir, "benign")
    os.makedirs(malware_dir, exist_ok=True)
    os.makedirs(benign_dir, exist_ok=True)

    # Sauvegarder les fichiers malware
    malware_paths: list[str] = []
    for upload in malware_files:
        content: bytes = await upload.read()
        if len(content) > settings.max_file_size_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Fichier trop volumineux : {upload.filename} "
                f"({len(content)} bytes > {settings.max_file_size_bytes})",
            )
        file_path: str = os.path.join(malware_dir, upload.filename or f"malware_{len(malware_paths)}")
        with open(file_path, "wb") as fh:
            fh.write(content)
        malware_paths.append(file_path)

    # Sauvegarder les fichiers bénins
    benign_paths: list[str] = []
    for upload in benign_files:
        content = await upload.read()
        if len(content) > settings.max_file_size_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Fichier trop volumineux : {upload.filename} "
                f"({len(content)} bytes > {settings.max_file_size_bytes})",
            )
        file_path = os.path.join(benign_dir, upload.filename or f"benign_{len(benign_paths)}")
        with open(file_path, "wb") as fh:
            fh.write(content)
        benign_paths.append(file_path)

    # Sauvegarder le bundle M1 (optionnel)
    m1_bundle_path: str | None = None
    if m1_bundle is not None:
        m1_content: bytes = await m1_bundle.read()
        m1_bundle_path = os.path.join(job_dir, "m1_bundle.json")
        with open(m1_bundle_path, "wb") as fh:
            fh.write(m1_content)

    # Parser mitre_attack
    mitre_list: list[str] | None = None
    if mitre_attack:
        mitre_list = [m.strip() for m in mitre_attack.split(",") if m.strip()]

    # Créer le job
    job_id: str = uuid.uuid4().hex[:16]
    corpus_id: str = f"corpus_{job_id}"

    job: GenerationJob = GenerationJob(
        job_id=job_id,
        corpus_id=corpus_id,
        status_url=f"/api/v1/jobs/{job_id}",
    )

    # Stocker le job et l'enqueuer
    request.app.state.jobs[job_id] = job
    await request.app.state.job_queue.put({
        "job_id": job_id,
        "malware_paths": malware_paths,
        "benign_paths": benign_paths,
        "corpus_id": corpus_id,
        "m1_bundle_path": m1_bundle_path,
        "malware_family": malware_family,
        "mitre_attack": mitre_list,
    })

    logger.info(
        "generation_job_created",
        job_id=job_id,
        corpus_id=corpus_id,
        malware_files=len(malware_paths),
        benign_files=len(benign_paths),
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "status_url": f"/api/v1/jobs/{job_id}",
    }


@router.get("/generate/capabilities")
async def get_capabilities() -> dict[str, Any]:
    """Retourne les capacités du moteur de génération YARA."""
    settings = get_settings()

    return {
        "supported_formats": ["pe", "elf", "text", "generic"],
        "export_formats": ["yar", "json", "stix", "csv"],
        "algorithm": "tfidf_discriminant",
        "m1_integration": settings.m1_integration_enabled,
        "max_file_size_mb": settings.max_file_size_bytes // (1024 * 1024),
        "delta_threshold": settings.delta_threshold,
    }

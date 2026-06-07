"""
Module   : admap_m2.api.routers.analyze
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.models.job, admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from admap_m2.api.dependencies import get_queue, get_app_settings
from admap_m2.core.config import Settings
from admap_m2.models.job import AnalysisOptions
from admap_m2.pipeline.job_queue import JobQueue
from admap_m2.parsers.pcap_parser import SCAPY_AVAILABLE

try:
    from admap_m1.models.ioc import IOCBundle  # noqa: F401
    M1_AVAILABLE = True
except ImportError:
    M1_AVAILABLE = False

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def analyze_pcap(
    file: UploadFile = File(..., description="Fichier PCAP à analyser (.pcap, .pcapng, .cap)"),
    enable_beaconing: bool = Form(True),
    enable_dga: bool = Form(True),
    enable_dns_tunnel: bool = Form(True),
    enable_http_c2: bool = Form(True),
    enable_tls: bool = Form(True),
    enable_irc: bool = Form(True),
    enable_port_scan: bool = Form(True),
    m1_bundle_path: str = Form(""),
    min_confidence: int = Form(20),
    queue: JobQueue = Depends(get_queue),
    settings: Settings = Depends(get_app_settings),
) -> dict:
    """
    Upload un fichier PCAP et lance l'analyse C2 en mode asynchrone.

    Returns:
        202 avec job_id, status, status_url.

    Raises:
        HTTPException 400: Fichier manquant ou illisible.
        HTTPException 413: Fichier trop volumineux.
        HTTPException 422: Extension non supportée.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing")

    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file extension: {ext}. Allowed: {settings.ALLOWED_EXTENSIONS}",
        )

    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    max_bytes = settings.MAX_PCAP_SIZE_MB * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size is {settings.MAX_PCAP_SIZE_MB} MB",
        )

    options = AnalysisOptions(
        enable_beaconing=enable_beaconing,
        enable_dga=enable_dga,
        enable_dns_tunnel=enable_dns_tunnel,
        enable_http_c2=enable_http_c2,
        enable_tls=enable_tls,
        enable_irc=enable_irc,
        enable_port_scan=enable_port_scan,
        m1_bundle_path=m1_bundle_path or None,
        min_confidence_threshold=min_confidence,
    )

    job = queue.submit_job(
        filename=file.filename,
        file_bytes=file_bytes,
        options=options,
    )

    return {
        "job_id": str(job.job_id),
        "status": job.status.value,
        "status_url": f"/api/v1/jobs/{job.job_id}",
    }


@router.get("/capabilities", tags=["analyze"])
async def get_capabilities() -> dict:
    """
    Retourne les capacités des détecteurs disponibles.

    Returns:
        Dictionnaire des détecteurs et intégrations disponibles.
    """
    return {
        "detectors": [
            "beaconing", "dga", "dns_tunnel", "http_c2",
            "tls_suspect", "irc_c2", "port_scan",
        ],
        "scapy_available": SCAPY_AVAILABLE,
        "m1_integration": M1_AVAILABLE,
    }

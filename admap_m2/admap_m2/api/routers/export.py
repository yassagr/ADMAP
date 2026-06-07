"""
Module   : admap_m2.api.routers.export
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.exporters, admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

import io
import zipfile
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response

from admap_m2.api.dependencies import get_queue
from admap_m2.core.exceptions import JobNotFoundError
from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter
from admap_m2.exporters.stix_exporter import STIXExporter
from admap_m2.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/export", tags=["export"])

_exporters = {
    "json": (JSONExporter(), "application/json", ".alerts.json"),
    "csv": (CSVExporter(), "text/csv", ".alerts.csv"),
    "stix": (STIXExporter(), "application/json", ".stix.json"),
}


def _resolve_bundle(job_id: UUID, queue: JobQueue):
    """Résout un AlertBundle depuis un job_id."""
    try:
        bundle = queue.get_job_result(job_id)
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail=f"Result not available for job {job_id}",
        )
    return bundle


@router.get("/{job_id}/json")
async def export_json(job_id: UUID, queue: JobQueue = Depends(get_queue)) -> Response:
    """Exporte l'AlertBundle au format JSON natif ADMAP."""
    bundle = _resolve_bundle(job_id, queue)
    exporter, media_type, _ = _exporters["json"]
    return Response(content=exporter.export(bundle), media_type=media_type)


@router.get("/{job_id}/csv")
async def export_csv(job_id: UUID, queue: JobQueue = Depends(get_queue)) -> Response:
    """Exporte l'AlertBundle au format CSV pour SIEM."""
    bundle = _resolve_bundle(job_id, queue)
    exporter, media_type, _ = _exporters["csv"]
    return Response(content=exporter.export(bundle), media_type=media_type)


@router.get("/{job_id}/stix")
async def export_stix(job_id: UUID, queue: JobQueue = Depends(get_queue)) -> Response:
    """Exporte l'AlertBundle au format STIX 2.1."""
    bundle = _resolve_bundle(job_id, queue)
    try:
        exporter, media_type, _ = _exporters["stix"]
        return Response(content=exporter.export(bundle), media_type=media_type)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{job_id}/all")
async def export_all(job_id: UUID, queue: JobQueue = Depends(get_queue)) -> Response:
    """Exporte l'AlertBundle dans un ZIP contenant JSON + CSV + STIX."""
    bundle = _resolve_bundle(job_id, queue)
    zip_buffer = io.BytesIO()
    stem = bundle.pcap_filename.rsplit(".", 1)[0]
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for fmt, (exporter, _, ext) in _exporters.items():
            try:
                content = exporter.export(bundle)
                zf.writestr(f"{stem}{ext}", content)
            except Exception:
                pass  # stix optionnel si bibliothèque absente
    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{stem}_alerts.zip"'},
    )

"""
Module   : admap_m2.api.routers.export
Version  : 1.0.0
Dépend   : [fastapi, admap_m2.pipeline.job_queue]
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

from admap_m2.api.dependencies import get_queue
from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter
from admap_m2.exporters.stix_exporter import STIXExporter
from admap_m2.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/{bundle_id}/{fmt}")
async def export_bundle(
    bundle_id: str,
    fmt: str,
    queue: JobQueue = Depends(get_queue)
) -> Response:
    """Exporte un AlertBundle au format demandé (json, csv, stix)."""
    bundle = queue.get_result(bundle_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="AlertBundle not found")

    fmt = fmt.lower()
    if fmt == "json":
        exporter = JSONExporter()
        content = exporter.export(bundle)
        media_type = "application/json"
    elif fmt == "csv":
        exporter = CSVExporter()
        content = exporter.export(bundle)
        media_type = "text/csv"
    elif fmt == "stix":
        try:
            exporter = STIXExporter()
            content = exporter.export(bundle)
            media_type = "application/json"
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")

    return Response(content=content, media_type=media_type)

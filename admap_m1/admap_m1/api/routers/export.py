"""
Module   : admap_m1.api.routers.export
Version  : 3.0.0
Dépend   : [fastapi, admap_m1.exporters]

Routeur pour l'exportation des résultats dans des formats CTI standards.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from admap_m1.api.dependencies import get_queue
from admap_m1.core.exceptions import JobNotFoundError
from admap_m1.exporters.cytomic_exporter import CytomicExporter
from admap_m1.exporters.misp_exporter import MISPExporter
from admap_m1.exporters.openioc_exporter import OpenIOCExporter
from admap_m1.exporters.stix_exporter import STIXExporter
from admap_m1.models.job import JobStatus
from admap_m1.pipeline.job_queue import JobQueue

router = APIRouter(prefix="/export", tags=["Export"])

EXPORTERS = {
    "stix21": STIXExporter(),
    "openioc": OpenIOCExporter(),
    "misp": MISPExporter(),
    "cytomic": CytomicExporter(),
}


@router.get("/{job_id}")
async def export_job_result(
    job_id: UUID,
    format: str = Query(..., description="Format d'export (stix21, openioc, misp, cytomic)"),
    queue: JobQueue = Depends(get_queue)
):
    """Exporte les IOCs d'une analyse terminée vers un format CTI standard."""
    fmt = format.lower()
    if fmt not in EXPORTERS:
        raise HTTPException(
            status_code=400,
            detail=f"Format non supporté. Formats valides : {list(EXPORTERS.keys())}"
        )

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

        exporter = EXPORTERS[fmt]
        exported_data = exporter.export(result)
        
        # Le content-type dépend du format
        media_type = "application/xml" if fmt == "openioc" else "application/json"
        
        return PlainTextResponse(content=exported_data, media_type=media_type)
        
    except JobNotFoundError:
        raise HTTPException(status_code=404, detail="Job introuvable")

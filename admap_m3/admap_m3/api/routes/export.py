"""
Module   : admap_m3.api.routes.export
Version  : 1.0.0
Dépend   : [fastapi, structlog]

Endpoints d'export des résultats dans différents formats :
yar, json, stix, csv, all (ZIP).
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse

from admap_m3.exporters.csv_exporter import CSVExporter
from admap_m3.exporters.json_exporter import JSONExporter
from admap_m3.exporters.stix_exporter import STIXExporter
from admap_m3.exporters.yara_exporter import YaraFileExporter
from admap_m3.models.job import GenerationJob, GenerationStatus
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

router: APIRouter = APIRouter(tags=["Export"])


def _get_completed_ruleset(request: Request, job_id: str) -> YaraRuleSet:
    """Récupère le YaraRuleSet d'un job terminé. Lève HTTPException sinon."""
    jobs: dict[str, GenerationJob] = request.app.state.jobs

    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job introuvable : {job_id}")

    job: GenerationJob = jobs[job_id]
    if job.status != GenerationStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Job en statut '{job.status.value}' — export impossible",
        )

    results: dict[str, Any] = request.app.state.results
    if job_id not in results:
        raise HTTPException(status_code=404, detail="Résultat introuvable")

    result: Any = results[job_id]
    if isinstance(result, YaraRuleSet):
        return result
    # Si stocké comme dict (sérialisé)
    return YaraRuleSet.model_validate(result)


@router.get("/export/{job_id}/yar")
async def export_yar(request: Request, job_id: str) -> Response:
    """Export au format YARA (.yar)."""
    ruleset: YaraRuleSet = _get_completed_ruleset(request, job_id)

    tmp_dir: str = tempfile.mkdtemp(prefix="admap_m3_export_")
    output_path: str = os.path.join(tmp_dir, f"{ruleset.ruleset_id}.yar")

    exporter: YaraFileExporter = YaraFileExporter()
    result: dict[str, Any] = exporter.export(ruleset, output_path)

    if result["status"] != "ok":
        raise HTTPException(status_code=500, detail=result.get("error", "Export échoué"))

    return FileResponse(
        path=output_path,
        media_type="text/plain",
        filename=f"{ruleset.ruleset_id}.yar",
    )


@router.get("/export/{job_id}/json")
async def export_json(request: Request, job_id: str) -> Response:
    """Export au format JSON."""
    ruleset: YaraRuleSet = _get_completed_ruleset(request, job_id)

    tmp_dir: str = tempfile.mkdtemp(prefix="admap_m3_export_")
    output_path: str = os.path.join(tmp_dir, f"{ruleset.ruleset_id}.json")

    exporter: JSONExporter = JSONExporter()
    result: dict[str, Any] = exporter.export(ruleset, output_path)

    if result["status"] != "ok":
        raise HTTPException(status_code=500, detail=result.get("error", "Export échoué"))

    return FileResponse(
        path=output_path,
        media_type="application/json",
        filename=f"{ruleset.ruleset_id}.json",
    )


@router.get("/export/{job_id}/stix")
async def export_stix(request: Request, job_id: str) -> Response:
    """Export au format STIX 2.1."""
    ruleset: YaraRuleSet = _get_completed_ruleset(request, job_id)

    tmp_dir: str = tempfile.mkdtemp(prefix="admap_m3_export_")
    output_path: str = os.path.join(tmp_dir, f"{ruleset.ruleset_id}_stix.json")

    exporter: STIXExporter = STIXExporter()
    result: dict[str, Any] = exporter.export(ruleset, output_path)

    if result["status"] != "ok":
        raise HTTPException(status_code=500, detail=result.get("error", "Export échoué"))

    return FileResponse(
        path=output_path,
        media_type="application/json",
        filename=f"{ruleset.ruleset_id}_stix.json",
    )


@router.get("/export/{job_id}/csv")
async def export_csv(request: Request, job_id: str) -> Response:
    """Export au format CSV."""
    ruleset: YaraRuleSet = _get_completed_ruleset(request, job_id)

    tmp_dir: str = tempfile.mkdtemp(prefix="admap_m3_export_")
    output_path: str = os.path.join(tmp_dir, f"{ruleset.ruleset_id}.csv")

    exporter: CSVExporter = CSVExporter()
    result: dict[str, Any] = exporter.export(ruleset, output_path)

    if result["status"] != "ok":
        raise HTTPException(status_code=500, detail=result.get("error", "Export échoué"))

    return FileResponse(
        path=output_path,
        media_type="text/csv",
        filename=f"{ruleset.ruleset_id}.csv",
    )


@router.get("/export/{job_id}/all")
async def export_all(request: Request, job_id: str) -> StreamingResponse:
    """Export de tous les formats dans un ZIP."""
    ruleset: YaraRuleSet = _get_completed_ruleset(request, job_id)

    tmp_dir: str = tempfile.mkdtemp(prefix="admap_m3_export_")

    # Exporter dans chaque format
    exporters: list[tuple[str, Any]] = [
        (f"{ruleset.ruleset_id}.yar", YaraFileExporter()),
        (f"{ruleset.ruleset_id}.json", JSONExporter()),
        (f"{ruleset.ruleset_id}_stix.json", STIXExporter()),
        (f"{ruleset.ruleset_id}.csv", CSVExporter()),
    ]

    exported_files: list[str] = []
    for filename, exporter in exporters:
        output_path = os.path.join(tmp_dir, filename)
        result = exporter.export(ruleset, output_path)
        if result["status"] == "ok":
            exported_files.append(output_path)

    # Créer le ZIP en mémoire
    zip_buffer: io.BytesIO = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in exported_files:
            zf.write(file_path, os.path.basename(file_path))

    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{ruleset.ruleset_id}_all.zip"'
        },
    )

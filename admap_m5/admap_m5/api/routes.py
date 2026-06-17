from __future__ import annotations
import asyncio
import uuid
import structlog
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse

from admap_m5.config import get_settings
from admap_m5.models.input import AttributionRequest, AttributionOptions
from admap_m5.models.job import AttributionJob, JobStatus
from admap_m5.worker.attribution_worker import run_attribution_job
from admap_m5.exporters.json_exporter import JSONExporter
from admap_m5.exporters.csv_exporter import CSVExporter
from admap_m5.exporters.stix_exporter import STIXExporter

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/health")
async def health() -> dict:
    settings = get_settings()
    return {"status": "ok", "version": settings.version, "module": "M5-Attribution"}


@router.get("/ready")
async def ready(request: Request) -> dict:
    settings = get_settings()
    queue: asyncio.Queue = request.app.state.job_queue
    kb_ok = settings.apt_kb_path.exists()
    model_ok = settings.xgb_model_path.exists()
    return {
        "status": "ok" if kb_ok else "degraded",
        "version": settings.version,
        "queue_size": queue.qsize(),
        "apt_kb_available": kb_ok,
        "xgb_model_available": model_ok,
        "m4_integration": True,
    }


@router.post("/api/v1/analyze", status_code=202)
async def analyze(
    request: Request,
    apt_map_report: UploadFile = File(..., description="APTMapReport JSON de M4"),
    ioc_bundle: UploadFile | None = File(default=None, description="IOCBundle JSON de M1 (optionnel)"),
    alert_bundle: UploadFile | None = File(default=None, description="AlertBundle JSON de M2 (optionnel)"),
    options: str | None = Form(default=None, description="AttributionOptions JSON serialise"),
) -> dict:
    """Soumet un job d'attribution. Retourne 202 avec job_id."""
    settings = get_settings()
    queue: asyncio.Queue = request.app.state.job_queue
    jobs: dict = request.app.state.jobs

    if queue.full():
        raise HTTPException(status_code=503, detail="Job queue is full")

    apt_map_report_bytes = await apt_map_report.read()
    ioc_bytes = await ioc_bundle.read() if ioc_bundle else None
    alert_bytes = await alert_bundle.read() if alert_bundle else None

    try:
        parsed_options = AttributionOptions.model_validate_json(options) if options else AttributionOptions()
    except Exception:
        parsed_options = AttributionOptions()

    job_id = str(uuid.uuid4())
    job = AttributionJob(job_id=job_id, status=JobStatus.PENDING)
    jobs[job_id] = job

    asyncio.create_task(
        run_attribution_job(
            job_id=job_id,
            jobs=jobs,
            apt_map_report_json=apt_map_report_bytes.decode("utf-8", errors="replace"),
            ioc_bundle_json=ioc_bytes.decode("utf-8", errors="replace") if ioc_bytes else None,
            alert_bundle_json=alert_bytes.decode("utf-8", errors="replace") if alert_bytes else None,
            options=parsed_options,
            settings=settings,
        )
    )

    logger.info("api.job_submitted", job_id=job_id)
    return {
        "job_id": job_id,
        "status": "pending",
        "status_url": f"/api/v1/jobs/{job_id}",
    }


@router.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> dict:
    jobs: dict = request.app.state.jobs
    job: AttributionJob | None = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.model_dump(mode="json")


@router.get("/api/v1/jobs/{job_id}/result")
async def get_result(job_id: str, request: Request) -> dict:
    jobs: dict = request.app.state.jobs
    job: AttributionJob | None = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.COMPLETED:
        raise HTTPException(status_code=409, detail=f"Job not completed (status: {job.status})")
    if job.result is None:
        raise HTTPException(status_code=500, detail="Job completed but result is None")
    return job.result.model_dump(mode="json")


@router.delete("/api/v1/jobs/{job_id}", status_code=200)
async def cancel_job(job_id: str, request: Request) -> dict:
    jobs: dict = request.app.state.jobs
    job: AttributionJob | None = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
        raise HTTPException(status_code=409, detail=f"Cannot cancel job in status: {job.status}")
    jobs[job_id] = job.model_copy(update={"status": JobStatus.CANCELLED})
    return {"job_id": job_id, "status": "cancelled"}


@router.get("/api/v1/export/{job_id}/{export_format}")
async def export_result(job_id: str, export_format: str, request: Request) -> JSONResponse:
    """Export du rapport en json | csv | stix | all.
    
    Ne leve jamais RuntimeError — retourne un JSON d'erreur structure.
    """
    jobs: dict = request.app.state.jobs
    job: AttributionJob | None = jobs.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "Job not found", "job_id": job_id})
    if job.status != JobStatus.COMPLETED or job.result is None:
        return JSONResponse(status_code=409, content={"error": "Job not completed", "status": str(job.status)})

    report = job.result
    valid_formats = {"json", "csv", "stix", "all"}
    if export_format not in valid_formats:
        return JSONResponse(status_code=400, content={"error": f"Invalid format: {export_format}", "valid": list(valid_formats)})

    result_parts: dict[str, object] = {}
    errors: list[str] = []

    if export_format in ("json", "all"):
        out = JSONExporter().export(report)
        if "error" in out:
            errors.append(f"json: {out['error']}")
        else:
            result_parts["json"] = out

    if export_format in ("csv", "all"):
        out = CSVExporter().export(report)
        if "error" in out:
            errors.append(f"csv: {out['error']}")
        else:
            result_parts["csv"] = out

    if export_format in ("stix", "all"):
        out = STIXExporter().export(report)
        if "error" in out:
            errors.append(f"stix: {out['error']}")
        else:
            result_parts["stix"] = out

    if errors and not result_parts:
        return JSONResponse(status_code=500, content={"errors": errors, "job_id": job_id})

    if export_format == "all":
        return JSONResponse(content={"job_id": job_id, "exports": result_parts, "errors": errors})
    else:
        key = export_format
        return JSONResponse(content=result_parts.get(key, {"error": "export failed"}))


@router.get("/api/v1/capabilities")
async def capabilities() -> dict:
    settings = get_settings()
    return {
        "module": "M5-Attribution",
        "version": settings.version,
        "inputs": ["APTMapReport (M4, required)", "IOCBundle (M1, optional)", "AlertBundle (M2, optional)"],
        "outputs": ["AttributionReport (JSON, CSV, STIX 2.1)"],
        "methods": ["XGBoost classification", "Cosine similarity TF-IDF"],
        "apt_groups_in_kb": "dynamic (loaded from apt_kb.json)",
        "top_k_default": settings.top_k_candidates,
    }

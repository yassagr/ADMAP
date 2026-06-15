from __future__ import annotations
import uuid
import json
import asyncio
from fastapi import APIRouter, Request, UploadFile, File, Form, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from typing import Any

from admap_m4.models.report import AnalysisJob, AnalysisOptions, JobStatus
from admap_m4.config import get_settings
from admap_m4.exporters.json_exporter import JSONExporter
from admap_m4.exporters.csv_exporter import CSVExporter
from admap_m4.exporters.stix_exporter import STIXExporter

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok", "version": "1.0.0", "module": "M4-APTMapper"}

@router.get("/ready", status_code=status.HTTP_200_OK)
async def ready(request: Request):
    if not hasattr(request.app.state, "job_queue"):
        raise HTTPException(status_code=503, detail="Queue non initialisée")
    return {
        "status": "ready",
        "version": get_settings().version,
        "queue_size": request.app.state.job_queue.qsize(),
        "m2_integration": True,
        "m3_integration": True
    }

@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED)
async def analyze(
    request: Request,
    alert_bundle: UploadFile = File(...),
    ioc_bundle: UploadFile | None = File(None),
    yara_ruleset: UploadFile | None = File(None),
    options: str | None = Form(None)
):
    try:
        alert_json = await alert_bundle.read()
        alert_json_str = alert_json.decode("utf-8")
        
        ioc_json_str = None
        if ioc_bundle:
            ioc_json = await ioc_bundle.read()
            ioc_json_str = ioc_json.decode("utf-8")
            
        yara_json_str = None
        if yara_ruleset:
            yara_json = await yara_ruleset.read()
            yara_json_str = yara_json.decode("utf-8")
            
        analysis_options = AnalysisOptions()
        if options:
            options_dict = json.loads(options)
            analysis_options = AnalysisOptions(**options_dict)
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid request data: {e}")

    job_id = str(uuid.uuid4())
    job = AnalysisJob(
        job_id=job_id,
        options=analysis_options,
        metadata={
            "alert_bundle_json": alert_json_str,
            "ioc_bundle_json": ioc_json_str,
            "yara_ruleset_json": yara_json_str
        }
    )
    
    request.app.state.jobs[job_id] = job
    try:
        request.app.state.job_queue.put_nowait(job_id)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Job queue is full")

    return {
        "job_id": job_id,
        "status": "pending",
        "status_url": f"/api/v1/jobs/{job_id}"
    }

@router.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # Hide large metadata before returning
    job_dump = job.model_dump()
    job_dump.pop("metadata", None)
    return job_dump

@router.get("/jobs/{job_id}/result")
async def get_job_result(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.completed:
        raise HTTPException(status_code=409, detail={"error": "job_not_completed", "status": job.status})
    return job.result

@router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status in (JobStatus.completed, JobStatus.failed, JobStatus.cancelled):
        return {"cancelled": False, "status": job.status}
    job.status = JobStatus.cancelled
    return {"cancelled": True}

@router.get("/export/{job_id}/{format}")
async def export_job(job_id: str, format: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.completed or not job.result:
        raise HTTPException(status_code=409, detail={"error": "job_not_completed"})

    if format == "json":
        result = JSONExporter().export(job.result)
        return JSONResponse(content=result)
    elif format == "csv":
        result_csv = CSVExporter().export(job.result)
        return PlainTextResponse(content=result_csv, media_type="text/csv")
    elif format == "stix":
        result_stix = STIXExporter().export(job.result)
        return JSONResponse(content=result_stix, media_type="application/stix+json")
    elif format == "all":
        return {
            "json": JSONExporter().export(job.result),
            "csv": CSVExporter().export(job.result),
            "stix": STIXExporter().export(job.result)
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

@router.get("/capabilities")
async def get_capabilities():
    return {
         "module": "M4",
         "version": get_settings().version,
         "algorithms": ["TF-IDF-manual", "DBSCAN-manual"],
         "inputs": ["AlertBundle-M2", "IOCBundle-M1-optional", "YaraRuleSet-M3-optional"],
         "outputs": ["APTMapReport", "CampaignCluster", "STIX-2.1"],
         "mitre_techniques_supported": [
             "T1071", "T1071.001", "T1071.003", "T1071.004", "T1573",
             "T1573.001", "T1573.002", "T1008", "T1095", "T1571",
             "T1048", "T1048.003", "T1041", "T1030", "T1568",
             "T1568.002", "T1105", "T1046", "T1595", "T1595.001",
             "T1027", "T1486"
         ]
    }
